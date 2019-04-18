//
// Copyright (C) 2015-2019 Virgil Security Inc.
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

import XCTest
import VirgilSDK
import VirgilCrypto
import VSCRatchet
@testable import VirgilSDKRatchet

class IntegrationGroupTests: XCTestCase {
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func initChat(numberOfParticipants: Int) -> ([Card], [SecureChat]) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto))!
        cardVerifier.verifyVirgilSignature = false
        
        let client = RatchetClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        var cards = [Card]()
        var chats = [SecureChat]()
        
        for _ in 0..<numberOfParticipants {
            let identity = NSUUID().uuidString
            let keyPair = try! crypto.generateKeyPair(ofType: .ed25519)
            let tokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
                let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
                
                let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(virgilCrypto: crypto), appId: testConfig.AppId, ttl: 10050)
                
                completion(try! generator.generateToken(identity: identity), nil)
            })
            
            let cardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto), accessTokenProvider: tokenProvider, cardVerifier: cardVerifier)
            cardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
            
            let cardManager = CardManager(params: cardManagerParams)
            
            let card = try! cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey).startSync().getResult()
            
            let params = try! KeychainStorageParams.makeKeychainStorageParams(appName: "test")
            let longTermKeysStorage = try! KeychainLongTermKeysStorage(identity: identity, params: params)
            let oneTimeKeysStorage = FileOneTimeKeysStorage(identity: identity)
            
            let keysRotator = KeysRotator(crypto: crypto, identityPrivateKey: keyPair.privateKey, identityCardId: card.identifier, orphanedOneTimeKeyTtl: 5, longTermKeyTtl: 10, outdatedLongTermKeyTtl: 5, desiredNumberOfOneTimeKeys: IntegrationTests.desiredNumberOfOtKeys, longTermKeysStorage: longTermKeysStorage, oneTimeKeysStorage: oneTimeKeysStorage, client: client)
            
            let secureChat = SecureChat(crypto: crypto,
                                        identityPrivateKey: keyPair.privateKey,
                                        identityCard: card,
                                        accessTokenProvider: tokenProvider,
                                        client: client,
                                        longTermKeysStorage: longTermKeysStorage,
                                        oneTimeKeysStorage: oneTimeKeysStorage,
                                        sessionStorage: FileSessionStorage(identity: identity, crypto: crypto),
                                        groupSessionStorage: FileGroupSessionStorage(identity: identity, crypto: crypto),
                                        keysRotator: keysRotator)
            
            cards.append(card)
            chats.append(secureChat)
        }
        
        return (cards, chats)
    }
    
    func test1__encrypt_decrypt__random_uuid_messages__should_decrypt() {
        let num = 10
        
        let (cards1, chats1) = self.initChat(numberOfParticipants: num)
        
        let initMsg = try! chats1[0].startNewGroupSession(with: [Card](cards1.dropFirst()))
        
        var sessions = [SecureGroupSession]()
        
        for i in 0..<num {
            var localCards = cards1
            localCards.remove(at: i)
            
            let session = try! chats1[i].startGroupSession(with: localCards, using: initMsg)
            
            sessions.append(session)
        }
        
        try! Utils.encryptDecrypt100Times(groupSessions: sessions)
        
        let (cards2, chats2) = self.initChat(numberOfParticipants: num)
        
        let ticket1 = try! sessions[0].createChangeMembersTicket(add: cards2, remove: [])
        
        for i in 0..<num * 2 {
            if i < num {
                try! sessions[i].useChangeMembersTicket(ticket: ticket1, add: cards2, remove: [])
            }
            else {
                var localCards = cards1
                localCards.remove(at: i - num)
                
                let session = try! chats2[i - num].startGroupSession(with: cards1 + localCards, using:
                    ticket1)
                
                sessions.append(session)
            }
        }
        
        try! Utils.encryptDecrypt100Times(groupSessions: sessions)
        
        let (cards3, chats3) = self.initChat(numberOfParticipants: num)
        
        let ticket2 = try! sessions[num].createChangeMembersTicket(add: cards3, remove: cards1)
        sessions = [SecureGroupSession](sessions.dropFirst(num))
        
        for i in 0..<num * 2 {
            if i < num {
                try! sessions[i].useChangeMembersTicket(ticket: ticket2, add: cards3, remove: cards1)
            }
            else {
                var localCards = cards3
                localCards.remove(at: i - num)
                
                let session = try! chats3[i - num].startGroupSession(with: cards2 + localCards, using:
                    ticket2)
                
                sessions.append(session)
            }
        }
        
        try! Utils.encryptDecrypt100Times(groupSessions: sessions)
    }
}
