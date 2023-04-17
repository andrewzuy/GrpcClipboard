use crate::clipboard_package::shared_clipboard_client::SharedClipboardClient;
use crate::clipboard_package::{Clipboard, RoomId};
use crate::clipboard_package::ClipboardId;
use aes::cipher::{KeyInit, BlockEncrypt};
use serde::{Deserialize};
use std::{fs, path};
use std::io::{self, Write};
use aes::Aes256;
use aes::cipher::{BlockCipher, BlockDecrypt,generic_array::GenericArray};
use rand::{rngs::OsRng, RngCore};
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use tonic::transport::Channel;
use sha256::{digest, try_digest};
use std::{thread, time};
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

pub mod clipboard_package{
    tonic::include_proto!("clipboard_package");
}

#[derive(Debug,Deserialize)]
struct Config{
    Host:String,
    Room:String,
    Passkey:String
}

fn get_system_clipboard()->String{
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    let clipboard =match ctx.get_contents(){
        Ok(clipboard) => clipboard,
        Err(e) => "".to_string()
    };
    clipboard
}

fn set_system_clipboard(value:String){
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(value).unwrap();
}

fn encrypt_aes_256_cbc(plaintext: String, key: &[u8; 32]) -> String {
    let mut iv = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut iv);
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut ciphertext = iv.to_vec();
    let mut prev_block = iv;
    let plaintext = plaintext.as_bytes();
    for block in plaintext.chunks(16) {
        let mut plaintext_block = [0u8; 16];
        plaintext_block[..block.len()].copy_from_slice(block);
        for i in 0..16 {
            plaintext_block[i] ^= prev_block[i];
        }
        let mut ciphertext_block = plaintext_block.clone();
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut ciphertext_block));
        prev_block = ciphertext_block;
        ciphertext.extend_from_slice(&ciphertext_block);
    }
    CUSTOM_ENGINE.encode(ciphertext) 
}

fn decrypt_aes_256_cbc(ciphertext: String, key: &[u8; 32]) -> Option<String> {
    let ciphertext = match CUSTOM_ENGINE.decode(ciphertext){
        Ok(cipher) => cipher,
        Err(e) => Vec::new()
    };
    if ciphertext.len() < 16 {
        return None;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&ciphertext[..16]);
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut plaintext = vec![0u8; ciphertext.len() - 16];
    let mut prev_block = iv;
    for (i, block) in ciphertext[16..].chunks(16).enumerate() {
        if block.len() < 16 {
            let mut padded_block = [0u8; 16];
            padded_block[..block.len()].copy_from_slice(block);
            for j in block.len()..16 {
                padded_block[j] = 16 - (block.len() as u8);
            }
            block_cipher_decrypt(&mut plaintext[i * 16..], &cipher, &prev_block, &padded_block);
        } else {
            let mut decrypted_block = [0u8; 16];
            block_cipher_decrypt(&mut decrypted_block, &cipher, &prev_block, block);
            prev_block.copy_from_slice(&block[..16]);
            plaintext[i * 16..(i + 1) * 16].copy_from_slice(&decrypted_block);
        }
    }
    let padding = plaintext[plaintext.len() - 1] as usize;
    let unpadded_length = plaintext.len() - padding;
    plaintext.truncate(unpadded_length);
    let result = unsafe{String::from_utf8_unchecked(plaintext)};
    Some(result)
}

fn block_cipher_decrypt(output: &mut [u8], cipher: &Aes256, prev_block: &[u8], input: &[u8]) {
    let mut input_block = [0u8; 16];
    input_block.copy_from_slice(input);
    let mut output_block = input_block.clone();
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut output_block));
    for i in 0..16 {
        output[i] = output_block[i] ^ prev_block[i];
    }
}

async fn watch_clipboard(host:String, room:String, passkey:String){
    let one_second = time::Duration::from_secs(1);
    let digest_key = digest(passkey).clone();
    let digest_longkey = digest_key.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest_longkey[0..32]);
    let mut client = SharedClipboardClient::connect(host).await.unwrap();
    let room_id = RoomId{room:room.clone()};
    let mut previous_clipboardId = join_room(&mut client,&room_id).await.unwrap();
    loop{
        let clipboardId= match join_room(&mut client, &room_id).await{
            Ok(clipboardId) => clipboardId,
            Err(clipoardId) => previous_clipboardId.clone()

        };
        println!("Clipboard ID = {}", clipboardId.clipboard_id);
        let sys_clip_encoded = encrypt_aes_256_cbc(get_system_clipboard(), &key);
        let sys_clip_pure = get_system_clipboard();
        if clipboardId.clipboard_id != previous_clipboardId.clipboard_id{
            let mut retr_clip = match get_clipboard(&mut client, &clipboardId).await{
                Ok(clip) => clip,
                Err(e) => Clipboard { 
                    clipboard_id: Some(clipboardId.clone()),
                    data: sys_clip_encoded.clone()
                }
            };
            set_system_clipboard(decrypt_aes_256_cbc(retr_clip.data, &key).unwrap());
        } else  if format!("{:X}",md5::compute(sys_clip_pure.clone())) != clipboardId.clipboard_id {
            let mut clipboard = Clipboard { 
                clipboard_id: Some(ClipboardId { room_id: Some(room_id.clone()), clipboard_id: format!("{:X}",md5::compute(sys_clip_pure)) }),
                data:  sys_clip_encoded.clone() 
            };
            previous_clipboardId = match set_clipboard(&mut client, &clipboard).await{
                Ok(clipboard) => clipboard,
                Err(e) => previous_clipboardId
            }
        }

        println!("Clipboard text: \n {}", get_system_clipboard());
        thread::sleep(one_second);

    }
}

async fn join_room(client:&mut SharedClipboardClient<Channel>, room_id:&RoomId)-> Result<ClipboardId,Box<dyn std::error::Error>>{
    let request = tonic::Request::new(room_id.clone());
    let response = client.join_shared_room(request).await?.into_inner().clone();
    Ok(response)
}

async fn get_clipboard(client:&mut SharedClipboardClient<Channel>, clipboard_id:&ClipboardId)-> Result<Clipboard,Box<dyn std::error::Error>>{
    let request = tonic::Request::new(clipboard_id.clone());
    let response = client.get_clipboard(request).await?.into_inner().clone();
    Ok(response)
}

async fn set_clipboard(client:&mut SharedClipboardClient<Channel>, clipboard:&Clipboard)-> Result<ClipboardId,Box<dyn std::error::Error>>{
    let request = tonic::Request::new(clipboard.clone());
    let response = client.set_clipboard(request).await?.into_inner().clone();
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = fs::read_to_string("config.json")
        .expect("Should have been able to read the file");
    let conf:Config =  serde_json::from_str(&config).unwrap();
    let room = conf.Room.clone();
    let host = conf.Host.clone();
    let passkey = conf.Passkey.clone();
    let task = thread::spawn(move ||{watch_clipboard(host,room,passkey)});
    let handl = task.join();
    handl.unwrap().await;
    Ok(())
}