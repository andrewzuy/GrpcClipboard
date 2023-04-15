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

pub mod clipboard_package{
    tonic::include_proto!("clipboard_package");
}

#[derive(Debug,Deserialize)]
struct Config{
    Host:String,
    Room:String,
    Passkey:String
}

fn encrypt_aes_256_cbc(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut iv);
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut ciphertext = iv.to_vec();
    let mut prev_block = iv;
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
    ciphertext
}

fn decrypt_aes_256_cbc(ciphertext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    // Verify that the ciphertext is at least one block in length (IV + ciphertext)
    if ciphertext.len() < 16 {
        return None;
    }
    
    // Extract the initialization vector (IV) from the first block of the ciphertext
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&ciphertext[..16]);
    
    // Create an AES-256 cipher with the given key
    let cipher = Aes256::new(GenericArray::from_slice(key));
    
    // Create a buffer to hold the decrypted plaintext
    let mut plaintext = vec![0u8; ciphertext.len() - 16];
    
    // Decrypt the ciphertext in CBC mode
    let mut prev_block = iv;
    for (i, block) in ciphertext[16..].chunks(16).enumerate() {
        if block.len() < 16 {
            // Pad the last block if it is less than 16 bytes
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
    // Remove PKCS#7 padding from the plaintext
    let padding = plaintext[plaintext.len() - 1] as usize;
    let unpadded_length = plaintext.len() - padding;
    plaintext.truncate(unpadded_length);
    
    Some(plaintext)
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

async fn join_room(client:&mut SharedClipboardClient<Channel>, room_id:&RoomId)-> Result<ClipboardId,Box<dyn std::error::Error>>{
    let request = tonic::Request::new(room_id.clone());
    let response = client.join_shared_room(request).await?.into_inner().clone();
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = fs::read_to_string("config.json")
        .expect("Should have been able to read the file");
    let conf:Config =  serde_json::from_str(&config).unwrap();
    println!("Host={}, Room={}, Passkey={}",conf.Host.clone(), conf.Room.clone(), conf.Passkey.clone());

    let passcode = conf.Passkey.clone();
    let dig =  digest(passcode).clone();
    let digest_key = dig.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest_key[0..32]);
    let plaintext = conf.Room.as_bytes();
    let ciphertext = encrypt_aes_256_cbc(plaintext, &key);
    println!("Plaintext: {:?}", plaintext);
    println!("Ciphertext: {:?}", ciphertext);
    let decryptedtext = decrypt_aes_256_cbc(ciphertext.as_slice(), &key).unwrap();
    println!("De-Ciphertext: {:?}", String::from_utf8(decryptedtext).unwrap());

    let mut client = SharedClipboardClient::connect("http://[::1]:8080").await?;
    let room_id = RoomId{room:"dojo".to_string()};
    let response = join_room(&mut client, &room_id).await?.clone();
    let response_clone = response.clone();
    println!("Room={}, ClipboardId={:x}", response.room_id.unwrap().room, md5::compute(response.clipboard_id) ) ;
    let request = tonic::Request::new(response_clone);
    let response = client.get_clipboard(request);
    let cloned_response = response.await?.into_inner().clone();
    let clip_id_cloned = cloned_response.clipboard_id.unwrap().clone();
    let room = clip_id_cloned.room_id.unwrap().room.clone();
    let id = clip_id_cloned.clipboard_id.clone();
    let data = cloned_response.data.clone();
    println!("----------------GOT RESPONSE--------------");
    println!("Room={}, ClipboardId={}, ClipboardData={}", room, id, data);

    let paste = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let data = paste.to_string();
    let hash = md5::compute(&data);

    let new_clipboard = Clipboard{
        clipboard_id : Some(ClipboardId{
            room_id : Some(RoomId { room: room.clone()}),
            clipboard_id : format!("{:X}", hash )
        }),
        data : data.clone()
    };
    let response = client.set_clipboard(new_clipboard);
    println!("----------------SET RESPONSE--------------");
    println!("Room={}, ClipboardId={}, ClipboardData={}", room, format!("{:X}", hash ), data);
    println!("Returned from server ID={}", response.await?.into_inner().clipboard_id);
    Ok(())
}