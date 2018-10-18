//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilSDK
import VSCRatchet
import VirgilCryptoApiImpl

@objc(VSRSecureChat) open class SecureChat: NSObject {
    @objc public let identityPrivateKey: VirgilPrivateKey
    @objc public let client: RatchetClientProtocol
    @objc public let crypto = VirgilCrypto()

    @objc public init(client: RatchetClientProtocol) {
        self.client = client
        
        self.identityPrivateKey = try! self.crypto.generateKeyPair().privateKey

        super.init()
    }
    
    @objc open func startNewSession(withRecipientWithCard recipientCard: Card) throws -> SecureSession {
//        checkExistingSessionOnStart

        let publicKeySet = try self.client.getPublicKeySet(forRecipientCardId: recipientCard.identifier)
        
        let privateKeyData = self.crypto.exportPrivateKey(self.identityPrivateKey)
        
        
        return try SecureSession(identityPrivateKey: privateKeyData, publicKeySet: publicKeySet)
        
//
//        // Get recipient's credentials
//        self.client.getRecipientCardsSet(forCardsIds: [recipientCard.identifier]) { cardsSets, error in
//            guard error == nil else {
//                completion(nil, SecureChat.makeError(withCode: .obtainingRecipientCardsSet, description: "Error obtaining recipient cards set. Underlying error: \(error!.localizedDescription)"))
//                return
//            }
//
//            guard let cardsSets = cardsSets, cardsSets.count > 0 else {
//                completion(nil, SecureChat.makeError(withCode: .recipientSetEmpty, description: "Error obtaining recipient cards set. Empty set."))
//                return
//            }
//
//            // FIXME: Multiple sessions?
//            let cardsSet = cardsSets[0]
//
//            do {
//                let session = try self.startNewSession(withRecipientWithCard: recipientCard, recipientCardsSet: cardsSet, additionalData: additionalData)
//                completion(session, nil)
//                return
//            }
//            catch {
//                completion(nil, error)
//                return
//            }
//        }
    }
}
