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
     RoomToClipboardIdMap : Arc<Mutex<RefCell<HashMap<String,Clipboard>>>>
 }

 #[tonic::async_trait]
 impl SharedClipboard for SecureClipboard{
     async fn join_shared_room(&self, request: Request<RoomId>) -> Result<Response<ClipboardId>, Status> {
         let roomId = request.into_inner();
         let mut clipboard_data = Clipboard{ clipboard_id: Some(ClipboardId{room_id:Some(RoomId{room:"".to_string()}), clipboard_id :"".to_string()}),data:"".to_string()};
         if self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().contains_key(&roomId.room) {
             let map = self.RoomToClipboardIdMap.lock().unwrap().clone().into_inner();
             clipboard_data = map.get(&roomId.room).unwrap().clone();
         } else {
             let clonedMap = self.RoomToClipboardIdMap.lock().unwrap();
             let mut clonedMap = clonedMap.borrow_mut();
             clonedMap.insert(roomId.clone().room, clipboard_data.clone());
         }
         if debug{
            clearscreen::clear();
            for (room_id, clipboard_id) in self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().iter() {
                println!("------------------------------------------------------------------");
                println!("Room {} :: ClipboardId {}", room_id, clipboard_id.clone().clipboard_id.unwrap().clipboard_id); 
                println!("Value:: {}", clipboard_id.data)
            }
                println!("------------------------------------------------------------------");
        }
         let response = clipboard_data.clone().clipboard_id.unwrap();

         Ok(Response::new(response))
     }


     async fn get_clipboard(&self, request: Request<ClipboardId>) -> Result<Response<Clipboard>, Status> {
        let clipboardId = request.into_inner();
        let room = clipboardId.room_id.unwrap().room;
        let mut clipboard = Clipboard{ clipboard_id: Some(ClipboardId{room_id:Some(RoomId{room:"".to_string()}), clipboard_id :"".to_string()}),data:"".to_string()};
        if self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().contains_key(&room) {
            let map = self.RoomToClipboardIdMap.lock().unwrap().clone().into_inner();
            clipboard = map.get(&room).unwrap().clone();
        }
        Ok(Response::new(clipboard))
     }

     async fn set_clipboard(&self, request: Request<Clipboard>) -> Result<Response<ClipboardId>, Status> {
        let clipboard = request.into_inner();
        let room = clipboard.clone().clipboard_id.unwrap().room_id.unwrap().room.clone();
        self.RoomToClipboardIdMap.lock().unwrap().borrow_mut().insert(room, clipboard.clone());
         Ok(Response::new(clipboard.clone().clipboard_id.unwrap()))
     }
 }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = "0.0.0.0:8080".parse().unwrap();
    let clipboard_service = SecureClipboard::default();

    Server::builder().add_service(SharedClipboardServer::new(clipboard_service))
        .serve(address)
        .await?;
    Ok(())

}