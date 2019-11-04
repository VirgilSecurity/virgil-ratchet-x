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
import VirgilCryptoRatchet
@testable import VirgilSDKRatchet

class IntegrationGroupTests: XCTestCase {
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private var crypto: VirgilCrypto!
    
    private func initChat(numberOfParticipants: Int) throws -> ([Card], [SecureChat]) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        self.crypto = crypto
        
        let cardVerifier = VirgilCardVerifier(crypto: crypto)!
        cardVerifier.verifyVirgilSignature = false
        
        var cards = [Card]()
        var chats = [SecureChat]()
        
        for _ in 0..<numberOfParticipants {
            let identity = NSUUID().uuidString
            let keyPair = try! crypto.generateKeyPair(ofType: .ed25519)
            let tokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
                let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
                
                let generator = try! JwtGenerator(apiKey: privateKey,
                                                  apiPublicKeyIdentifier: testConfig.ApiKeyId,
                                                  crypto: crypto,
                                                  appId: testConfig.AppId,
                                                  ttl: 10050)
                
                completion(try! generator.generateToken(identity: identity), nil)
            })
            
            let cardManagerParams = CardManagerParams(crypto: crypto, accessTokenProvider: tokenProvider, cardVerifier: cardVerifier)
            cardManagerParams.cardClient = CardClient(accessTokenProvider: tokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
            
            let client = RatchetClient(accessTokenProvider: tokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
            
            let cardManager = CardManager(params: cardManagerParams)
            
            let card = try cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, identity: identity).startSync().get()
            
            let params = try KeychainStorageParams.makeKeychainStorageParams(appName: "test")
            let longTermKeysStorage = try KeychainLongTermKeysStorage(identity: identity, params: params)
            let oneTimeKeysStorage = FileOneTimeKeysStorage(identity: identity, crypto: crypto, identityPrivateKey: PrivateKeyWrapper(keyPair: keyPair))
            
            let keysRotator = KeysRotator(crypto: crypto, identityPrivateKey: PrivateKeyWrapper(keyPair: keyPair), identityCardId: card.identifier, orphanedOneTimeKeyTtl: 5, longTermKeyTtl: 10, outdatedLongTermKeyTtl: 5, desiredNumberOfOneTimeKeys: IntegrationTests.desiredNumberOfOtKeys, longTermKeysStorage: longTermKeysStorage, oneTimeKeysStorage: oneTimeKeysStorage, client: client)
            
            let secureChat = SecureChat(crypto: crypto,
                                        identityPrivateKey: PrivateKeyWrapper(keyPair: keyPair),
                                        identityCard: card,
                                        client: client,
                                        longTermKeysStorage: longTermKeysStorage,
                                        oneTimeKeysStorage: oneTimeKeysStorage,
                                        sessionStorage: FileSessionStorage(identity: identity, crypto: crypto, identityPrivateKey: PrivateKeyWrapper(keyPair: keyPair)),
                                        groupSessionStorage: try FileGroupSessionStorage(identity: identity, crypto: crypto, identityKeyPair: keyPair),
                                        keysRotator: keysRotator)
            
            cards.append(card)
            chats.append(secureChat)
        }
        
        return (cards, chats)
    }
    
    func test1__encrypt_decrypt__random_uuid_messages__should_decrypt() {
        do {
            let num = 10
            
            let (cards1, chats1) = try self.initChat(numberOfParticipants: num)
            
            let sessionId = try self.crypto.generateRandomData(ofSize: 32)
            
            let initMsg = try chats1[0].startNewGroupSession(sessionId: sessionId)
            
            var sessions = [SecureGroupSession]()
            
            for i in 0..<num {
                var localCards = cards1
                localCards.remove(at: i)
                
                let session = try chats1[i].startGroupSession(with: localCards, sessionId: sessionId, using: initMsg)
                
                sessions.append(session)
            }
            
            try Utils.encryptDecrypt100Times(groupSessions: sessions)
            
            let (cards2, chats2) = try self.initChat(numberOfParticipants: num)
            
            let ticket1 = try sessions[0].createChangeParticipantsTicket()
            
            for i in 0..<num * 2 {
                if i < num {
                    try sessions[i].updateParticipants(ticket: ticket1, addCards: cards2, removeCardIds: [])
                }
                else {
                    var localCards = cards2
                    localCards.remove(at: i - num)
                    
                    let session = try chats2[i - num].startGroupSession(with: cards1 + localCards, sessionId: sessionId, using:
                        ticket1)
                    
                    sessions.append(session)
                }
            }
            
            try Utils.encryptDecrypt100Times(groupSessions: sessions)
            
            let (cards3, chats3) = try self.initChat(numberOfParticipants: num)
            
            let ticket2 = try sessions[num].createChangeParticipantsTicket()
            sessions = [SecureGroupSession](sessions.dropFirst(num))
            
            for i in 0..<num * 2 {
                if i < num {
                    try sessions[i].updateParticipants(ticket: ticket2, addCards: cards3, removeCardIds: cards1.map { $0.identifier })
                }
                else {
                    var localCards = cards3
                    localCards.remove(at: i - num)
                    
                    let session = try chats3[i - num].startGroupSession(with: cards2 + localCards, sessionId: sessionId, using:
                        ticket2)
                    
                    sessions.append(session)
                }
            }
            
            try Utils.encryptDecrypt100Times(groupSessions: sessions)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }

    func test2__decrypt__old_session_messages__should_not_crash() {
        do {
            // Start group chat
            let num = 3

            let (cards, chats) = try self.initChat(numberOfParticipants: num)
            
            let sessionId = try self.crypto.generateRandomData(ofSize: 32)

            let initMsg = try chats.first!.startNewGroupSession(sessionId: sessionId)

            var sessions = [SecureGroupSession]()

            for i in 0..<num {
                var localCards = cards
                localCards.remove(at: i)

                let session = try chats[i].startGroupSession(with: localCards, sessionId: sessionId, using: initMsg)

                sessions.append(session)
            }

            // Encrypt plaintext
            let plainText = UUID().uuidString
            let message = try sessions.first!.encrypt(string: plainText)
            let decryptedMessage1 = try sessions.last!.decryptString(from: message, senderCardId: cards[0].identifier)
            XCTAssert(decryptedMessage1 == plainText)

            // Remove user
            let experimentalCard = cards.last!
            let removeCardIds = [experimentalCard.identifier]

            let removeTicket = try sessions.first!.createChangeParticipantsTicket()

            sessions.removeLast()

            for session in sessions {
                try session.updateParticipants(ticket: removeTicket, addCards: [], removeCardIds: removeCardIds)
            }

            // Return user
            let addTicket = try sessions.first!.createChangeParticipantsTicket()

            for session in sessions {
                try session.updateParticipants(ticket: addTicket, addCards: [experimentalCard], removeCardIds: [])
            }

            let newSession = try chats.last!.startGroupSession(with: cards.dropLast(), sessionId: sessionId, using: addTicket)
            sessions.append(newSession)

            // Decrypt with new session message, encrypted for old session
            _ = try? sessions.last!.decryptString(from: message, senderCardId: cards[0].identifier)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func test3__add_remove__user_100_times__should_not_crash() {
        do {
            // Start group chat
            let num = 3

            let (cards, chats) = try self.initChat(numberOfParticipants: num)
            
            let sessionId = try self.crypto.generateRandomData(ofSize: 32)

            let initMsg = try chats.first!.startNewGroupSession(sessionId: sessionId)

            var sessions = [SecureGroupSession]()

            for i in 0..<num {
                var localCards = cards
                localCards.remove(at: i)

                let session = try chats[i].startGroupSession(with: localCards, sessionId: sessionId, using: initMsg)

                sessions.append(session)
            }

            for _ in 1..<100 {
                // Remove user
                let experimentalCard = cards.last!
                let removeCardIds = [experimentalCard.identifier]

                let removeTicket = try sessions.first!.createChangeParticipantsTicket()

                sessions.removeLast()

                for session in sessions {
                    try session.updateParticipants(ticket: removeTicket, addCards: [], removeCardIds: removeCardIds)
                }

                // Return user
                let addTicket = try sessions.first!.createChangeParticipantsTicket()

                for session in sessions {
                    try session.updateParticipants(ticket: addTicket, addCards: [experimentalCard], removeCardIds: [])
                }

                let newSession = try chats.last!.startGroupSession(with: cards.dropLast(), sessionId: sessionId, using: addTicket)
                sessions.append(newSession)
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func test4__decrypt__wrong_sender__should_return_error() {
        do {
            let num = 3

            let (cards, chats) = try self.initChat(numberOfParticipants: num)

            let sessionId = try self.crypto.generateRandomData(ofSize: 32)

            let initMsg = try chats.first!.startNewGroupSession(sessionId: sessionId)

            var sessions = [SecureGroupSession]()

            for i in 0..<num {
                var localCards = cards
                localCards.remove(at: i)

                let session = try chats[i].startGroupSession(with: localCards, sessionId: sessionId, using: initMsg)

                sessions.append(session)
            }

            let str = UUID().uuidString
            let message = try sessions[0].encrypt(string: str)

            let decrypted = try sessions[1].decryptString(from: message, senderCardId: sessions[0].myIdentifier)
            XCTAssert(decrypted == str)

            let crypto = try! VirgilCrypto()

            do {
                _ = try sessions[1].decryptString(from: message, senderCardId: sessions[2].myIdentifier)
                XCTFail()
            }
            catch RatchetError.errorInvalidSignature {}
            catch {
                XCTFail()
            }

            do {
                let randomCardId = try crypto.generateRandomData(ofSize: 32).hexEncodedString()
                _ = try sessions[1].decryptString(from: message, senderCardId: randomCardId)
                XCTFail()
            }
            catch RatchetError.errorSenderNotFound {}
            catch {
                XCTFail()
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func test5__session_persistence__random_uuid_messages__should_decrypt() {
        do {
            let num = 10
            
            let (cards1, chats1) = try self.initChat(numberOfParticipants: num)
            
            let sessionId = try self.crypto.generateRandomData(ofSize: 32)
            
            let initMsg = try chats1[0].startNewGroupSession(sessionId: sessionId)
            
            var sessions = [SecureGroupSession]()
            
            for i in 0..<num {
                var localCards = cards1
                localCards.remove(at: i)
                
                let session = try chats1[i].startGroupSession(with: localCards, sessionId: sessionId, using: initMsg)
                
                sessions.append(session)
                
                try chats1[i].storeGroupSession(session)
            }
            
            try Utils.encryptDecrypt100TimesRestored(secureChats: chats1, sessionId: sessions[0].identifier)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}
