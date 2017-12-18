//
//  MessageFilterExtension.swift
//  Phishing Filter
//
//  Created by Carlos Irano on 16/12/17.
//  Copyright © 2017 Carlos Irano. All rights reserved.
//

import IdentityLookup

final class MessageFilterExtension: ILMessageFilterExtension {
    
    var words:[String] = ["N:E:T:", "$$$", "sou um spam"]
    var trust_senders:[String] = ["001", "002", "033"]
    var junk_senders:[String] = ["11974388635", "005", "006"]
    
//    let stack = CoreDataStack()
    
    func loadItems() {
//        let context = stack.persistentContainer.viewContext
//        let itemDAO = ItemDAO(managedObjectContext: context)
//        let allItems = itemDAO.fetchItmes()
//        self.words = allItems.flatMap({ item in
//            return item.value != nil ? item : nil
//        })
        
        // aqui ler o json do servidor e salvar local
        
        print("passei pelo loadItems")
    }
}

extension MessageFilterExtension: ILMessageFilterQueryHandling {
    
    func handle(_ queryRequest: ILMessageFilterQueryRequest, context: ILMessageFilterExtensionContext, completion: @escaping (ILMessageFilterQueryResponse) -> Void) {
        // First, check whether to filter using offline data (if possible).
        let offlineAction = self.offlineAction(for: queryRequest)
        
        switch offlineAction {
        case .allow, .filter:
            // Based on offline data, we know this message should either be Allowed or Filtered. Send response immediately.
            let response = ILMessageFilterQueryResponse()
            response.action = offlineAction
            
            completion(response)
            
        case .none:
            // Based on offline data, we do not know whether this message should be Allowed or Filtered. Defer to network.
            // Note: Deferring requests to network requires the extension target's Info.plist to contain a key with a URL to use. See documentation for details.
            context.deferQueryRequestToNetwork() { (networkResponse, error) in
                let response = ILMessageFilterQueryResponse()
                response.action = .none
                
                if let networkResponse = networkResponse {
                    // If we received a network response, parse it to determine an action to return in our response.
                    response.action = self.action(for: networkResponse)
                } else {
                    NSLog("Error deferring query request to network: \(String(describing: error))")
                }
                
                completion(response)
            }
        }
    }
    
    private func offlineAction(for queryRequest: ILMessageFilterQueryRequest) -> ILMessageFilterAction {
        
        self.loadItems()
        
        guard let messageSender = queryRequest.sender else {
            return .none
        }
        guard let messageBody = queryRequest.messageBody else {
            return .none
        }
        
        // check for sender
        for sender in trust_senders {
            if messageSender.contains(sender.lowercased()) {
                return .none
            }
        }
        
        for sender in junk_senders {
            if messageSender.contains(sender.lowercased()) {
                return .filter
            }
        }
        
        // check for keywords
        for word in self.words {
            if messageBody.contains(word.lowercased()) {
                return .filter
            }
        }
        
        return .none
    }
    
    private func action(for networkResponse: ILNetworkResponse) -> ILMessageFilterAction {
        // Replace with logic to parse the HTTP response and data payload of `networkResponse` to return an action.
        return .none
    }
}
