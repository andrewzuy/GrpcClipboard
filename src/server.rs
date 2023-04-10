use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use tonic::{transport::Server, Request, Response, Status};
use crate::clipboard_package::shared_clipboard_server::SharedClipboardServer;
use crate::clipboard_package::shared_clipboard_server::SharedClipboard;
use crate::clipboard_package::{Clipboard, RoomId};
use crate::clipboard_package::ClipboardId;
use std::sync::{Arc, Mutex};

pub mod clipboard_package{
    tonic::include_proto!("clipboard_package");
}

 #[derive(Debug, Default)]
 pub struct SecureClipboard {
     RoomToClipboardIdMap : Arc<Mutex<RefCell<HashMap<String,String>>>>
 }

 #[tonic::async_trait]
 impl SharedClipboard for SecureClipboard{

     fn new(&self)->Self
     {
         Ok(self);
     }

     async fn join_shared_room(&self, request: Request<RoomId>) -> Result<Response<ClipboardId>, Status> {
         let roomId = request.into_inner();
         let mut clipboardId: String::new();
         if self.RoomToClipboardIdMap.lock().unwrap().borrow().contains_key(&roomId.room) {
             let map = self.RoomToClipboardIdMap.lock().unwrap().into_inner();
             clipboardId = map.get(&roomId.room).unwrap().clone().as_str();
         } else {
             let clonedMap = self.RoomToClipboardIdMap.lock().unwrap();
             let mut clonedMap = clonedMap.borrow_mut();
             clonedMap.insert(roomId.clone().room, "".to_string());
         }

         let response = ClipboardId {

             room_id : Option::Some(roomId),
             clipboard_id: clipboardId.to_string()
         };

         Ok(Response::new(response))
     }


     async fn get_clipboard(&self, request: Request<ClipboardId>) -> Result<Response<Clipboard>, Status> {
         todo!()
     }

     async fn set_clipboard(&self, request: Request<Clipboard>) -> Result<Response<ClipboardId>, Status> {
         todo!()
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