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
import VirgilCryptoApiImpl
import VSCRatchet
@testable import VirgilSDKRatchet

class IntegrationTests: XCTestCase {
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func initChat() -> (Card, Card, SecureChat, SecureChat) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = VirgilCrypto()
        let receiverIdentityKeyPair = try! crypto.generateKeyPair(ofType: .FAST_EC_ED25519)
        let senderIdentityKeyPair = try! crypto.generateKeyPair(ofType: .FAST_EC_ED25519)
        
        let senderIdentity = NSUUID().uuidString
        let receiverIdentity = NSUUID().uuidString
        
        let receiverTokenProvider = CallbackJwtProvider(getJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!)
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: receiverIdentity), nil)
        })
        
        let senderTokenProvider = CallbackJwtProvider(getJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!)
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: senderIdentity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto())!
        cardVerifier.verifyVirgilSignature = false
        
        let cardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(), accessTokenProvider: receiverTokenProvider, cardVerifier: cardVerifier)
        cardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let cardManager = CardManager(params: cardManagerParams)
        
        let receiverCard = try! cardManager.publishCard(privateKey: receiverIdentityKeyPair.privateKey, publicKey: receiverIdentityKeyPair.publicKey).startSync().getResult()
        let senderCard = try! cardManager.publishCard(privateKey: senderIdentityKeyPair.privateKey, publicKey: senderIdentityKeyPair.publicKey).startSync().getResult()
        
        let receiverLongTermKeysStorage = try! KeychainLongTermKeysStorage(identity: receiverIdentity)
        
        let receiverOneTimeKeysStorage = FileOneTimeKeysStorage(identity: receiverIdentity)
        let senderOneTimeKeysStorage = FileOneTimeKeysStorage(identity: senderIdentity)

        let client = RatchetClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let receiverKeysRotator = KeysRotator(identityPrivateKey: receiverIdentityKeyPair.privateKey, identityCardId: receiverCard.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: 10, longTermKeysStorage: receiverLongTermKeysStorage, oneTimeKeysStorage: receiverOneTimeKeysStorage, client: client)
        
        
        let senderSecureChat = SecureChat(identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          accessTokenProvider: senderTokenProvider,
                                          client: client,
                                          longTermKeysStorage: try! KeychainLongTermKeysStorage(identity: senderIdentity),
                                          oneTimeKeysStorage: senderOneTimeKeysStorage,
                                          sessionStorage: FileSessionStorage(identity: senderIdentity),
                                          keysRotator: FakeKeysRotator())
        
        let receiverSecureChat = SecureChat(identityPrivateKey: receiverIdentityKeyPair.privateKey,
                                            accessTokenProvider: receiverTokenProvider,
                                            client: client,
                                            longTermKeysStorage: receiverLongTermKeysStorage,
                                            oneTimeKeysStorage: receiverOneTimeKeysStorage,
                                            sessionStorage: FileSessionStorage(identity: receiverIdentity),
                                            keysRotator: receiverKeysRotator)
        
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }
    
    func test1__encrypt_decrypt__random_uuid_messages__should_decrypt() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        try! receiverSecureChat.rotateKeys().startSync().getResult()
        
        let senderSession = try! senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().getResult()
        
        let plainText = UUID().uuidString
        let cipherText = try! senderSession.encrypt(string: plainText)
        
        let receiverSession = try! receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
        
        let decryptedMessage = try! receiverSession.decryptString(from: cipherText)
        
        XCTAssert(decryptedMessage == plainText)
        
        for _ in 0..<100 {
            let sender: SecureSession
            let receiver: SecureSession
            
            if Bool.random() {
                sender = senderSession
                receiver = receiverSession
            }
            else {
                sender = receiverSession
                receiver = senderSession
            }
            
            let plainText = UUID().uuidString
            
            let encryptedData = try! sender.encrypt(string: plainText)
            
            let decryptedMessage = try! receiver.decryptString(from: encryptedData)
            
            XCTAssert(decryptedMessage == plainText)
        }
    }
    
    func test2__session_persistence__random_uuid_messages__should_decrypt() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        _ = try! receiverSecureChat.rotateKeys().startSync().getResult()
        
        let senderSession = try! senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().getResult()
        
        XCTAssert(senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity) != nil)
        
        let plainText = UUID().uuidString
        let cipherText = try! senderSession.encrypt(string: plainText)
        
        let receiverSession = try! receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
        
        XCTAssert(receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity) != nil)
        
        let decryptedMessage = try! receiverSession.decryptString(from: cipherText)
        
        XCTAssert(decryptedMessage == plainText)
        
        for _ in 0..<100 {
            let sender: SecureSession
            let receiver: SecureSession
            
            if Bool.random() {
                sender = senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity)!
                receiver = receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity)!
            }
            else {
                sender = receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity)!
                receiver = senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity)!
            }
            
            let plainText = UUID().uuidString
            
            let message = try! sender.encrypt(string: plainText)
            
            let decryptedMessage = try! receiver.decryptString(from: message)
            
            XCTAssert(decryptedMessage == plainText)
        }
    }
}
