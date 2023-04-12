use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use tonic::{transport::Server, Request, Response, Status};
use crate::clipboard_package::shared_clipboard_client::SharedClipboardClient;
use crate::clipboard_package::{Clipboard, RoomId};
use crate::clipboard_package::ClipboardId;
use std::sync::{Arc, Mutex};
use md5::Digest;

pub mod clipboard_package{
    tonic::include_proto!("clipboard_package");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SharedClipboardClient::connect("http://[::1]:8080").await?;
    let room = String::from("Dojo");
    let request = tonic::Request::new(RoomId {
        room: room,
    });

    let response = client.join_shared_room(request).await?.into_inner().clone();
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