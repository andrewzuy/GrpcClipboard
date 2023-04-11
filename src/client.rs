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

    let request = tonic::Request::new(RoomId {
        room: "Dojo".into(),
    });

    let response = client.join_shared_room(request).await?.into_inner();

    println!("Roomd={}, ClipboardId={:x}", response.room_id.unwrap().room, md5::compute(response.clipboard_id) ) ;

    Ok(())

}