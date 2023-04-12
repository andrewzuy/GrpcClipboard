use std::cell::{RefCell};
use std::collections::HashMap;
use clearscreen;
use tonic::{transport::Server, Request, Response, Status};
use crate::clipboard_package::shared_clipboard_server::SharedClipboardServer;
use crate::clipboard_package::shared_clipboard_server::SharedClipboard;
use crate::clipboard_package::{Clipboard, RoomId};
use crate::clipboard_package::ClipboardId;
use std::sync::{Arc, Mutex};

static debug: bool = true;

pub mod clipboard_package{
    tonic::include_proto!("clipboard_package");
}

 #[derive(Debug, Default, Clone)]
 pub struct SecureClipboard {
     RoomToClipboardIdMap : Arc<Mutex<RefCell<HashMap<String,String>>>>
 }

 #[tonic::async_trait]
 impl SharedClipboard for SecureClipboard{
     async fn join_shared_room(&self, request: Request<RoomId>) -> Result<Response<ClipboardId>, Status> {
         let roomId = request.into_inner();
         let mut clipboard_data = String::new();
         if self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().contains_key(&roomId.room) {
             let map = self.RoomToClipboardIdMap.lock().unwrap().clone().into_inner();
             clipboard_data = map.get(&roomId.room).unwrap().clone();
         } else {
             let clonedMap = self.RoomToClipboardIdMap.lock().unwrap();
             let mut clonedMap = clonedMap.borrow_mut();
             clonedMap.insert(roomId.clone().room, "".to_string());
         }
         if debug{
            clearscreen::clear();
            for (room_id, clipboard_id) in self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().iter() {
                println!("------------------------------------------------");
                println!("Room {} :: ClipboardId {:X}", room_id, md5::compute(clipboard_id)); 
            }
                println!("------------------------------------------------");
        }
         let response = ClipboardId {

             room_id : Option::Some(roomId),
             clipboard_id: format!("{:X}", md5::compute(clipboard_data)) 
         };

         Ok(Response::new(response))
     }


     async fn get_clipboard(&self, request: Request<ClipboardId>) -> Result<Response<Clipboard>, Status> {
        let clipboardId = request.into_inner();
        let room = clipboardId.room_id.unwrap().room;
        let mut clipboardString = String::new();
        if self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().contains_key(&room) {
            let map = self.RoomToClipboardIdMap.lock().unwrap().clone().into_inner();
            clipboardString = map.get(&room).unwrap().clone();
        }
        let clone = clipboardString.clone();
        let hash = md5::compute(clipboardString);
        let response = Clipboard{
            clipboard_id : Some(ClipboardId{
                room_id : Some(RoomId { room: room.clone()}),
                clipboard_id : format!("{:X}", hash )
            }),
            data : clone
        };
        
        Ok(Response::new(response))
     }

     async fn set_clipboard(&self, request: Request<Clipboard>) -> Result<Response<ClipboardId>, Status> {
        let clipboard = request.into_inner();
        let room = clipboard.clipboard_id.unwrap().room_id.unwrap().room.clone();
        let room_clone = room.clone();
        let clip_data = clipboard.data.clone();
        let hash = md5::compute(clipboard.data);
        self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().insert(room, clip_data);
        let response = ClipboardId{
            room_id : Some(RoomId { room: room_clone}),
            clipboard_id : format!("{:X}", hash )
        };
         Ok(Response::new(response))
     }
 }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = "[::1]:8080".parse().unwrap();
    let clipboard_service = SecureClipboard::default();

    Server::builder().add_service(SharedClipboardServer::new(clipboard_service))
        .serve(address)
        .await?;
    Ok(())

}