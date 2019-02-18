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
        
        let receiverTokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!)
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: receiverIdentity), nil)
        })
        
        let senderTokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!)
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: senderIdentity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto())!
        cardVerifier.verifyVirgilSignature = false
        
        let senderCardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(), accessTokenProvider: senderTokenProvider, cardVerifier: cardVerifier)
        let receiverCardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(), accessTokenProvider: receiverTokenProvider, cardVerifier: cardVerifier)
        senderCardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        receiverCardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let senderCardManager = CardManager(params: senderCardManagerParams)
        let receiverCardManager = CardManager(params: receiverCardManagerParams)
        
        let receiverCard = try! receiverCardManager.publishCard(privateKey: receiverIdentityKeyPair.privateKey, publicKey: receiverIdentityKeyPair.publicKey).startSync().getResult()
        let senderCard = try! senderCardManager.publishCard(privateKey: senderIdentityKeyPair.privateKey, publicKey: senderIdentityKeyPair.publicKey).startSync().getResult()
        
        let receiverLongTermKeysStorage = try! KeychainLongTermKeysStorage(identity: receiverIdentity)
        let senderLongTermKeysStorage = try! KeychainLongTermKeysStorage(identity: senderIdentity)
        
        let receiverOneTimeKeysStorage = FileOneTimeKeysStorage(identity: receiverIdentity)
        let senderOneTimeKeysStorage = FileOneTimeKeysStorage(identity: senderIdentity)

        let client = RatchetClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let receiverKeysRotator = KeysRotator(identityPrivateKey: receiverIdentityKeyPair.privateKey, identityCardId: receiverCard.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: 10, longTermKeysStorage: receiverLongTermKeysStorage, oneTimeKeysStorage: receiverOneTimeKeysStorage, client: client)
        
        let senderKeysRotator = KeysRotator(identityPrivateKey: senderIdentityKeyPair.privateKey, identityCardId: senderCard.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: 10, longTermKeysStorage: senderLongTermKeysStorage, oneTimeKeysStorage: senderOneTimeKeysStorage, client: client)
        
        
        let senderSecureChat = SecureChat(identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          accessTokenProvider: senderTokenProvider,
                                          client: client,
                                          longTermKeysStorage: senderLongTermKeysStorage,
                                          oneTimeKeysStorage: senderOneTimeKeysStorage,
                                          sessionStorage: FileSessionStorage(identity: senderIdentity),
                                          keysRotator: senderKeysRotator)
        
        let receiverSecureChat = SecureChat(identityPrivateKey: receiverIdentityKeyPair.privateKey,
                                            accessTokenProvider: receiverTokenProvider,
                                            client: client,
                                            longTermKeysStorage: receiverLongTermKeysStorage,
                                            oneTimeKeysStorage: receiverOneTimeKeysStorage,
                                            sessionStorage: FileSessionStorage(identity: receiverIdentity),
                                            keysRotator: receiverKeysRotator)
        
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }
    
    func test__encrypt_decrypt__random_uuid_messages__should_decrypt() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        try! receiverSecureChat.rotateKeys().startSync().getResult()
        
        let senderSession = try! senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().getResult()
        
        let plainText = UUID().uuidString
        let cipherText = try! senderSession.encrypt(string: plainText)
        
        let receiverSession = try! receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
        
        let decryptedMessage = try! receiverSession.decryptString(from: cipherText)
        
        XCTAssert(decryptedMessage == plainText)
        
        Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
    }
    
    func test__session_persistence__random_uuid_messages__should_decrypt() {
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
        
        Utils.encryptDecrypt100TimesRestored(senderSecureChat: senderSecureChat, senderIdentity: senderCard.identity, receiverSecureChat: receiverSecureChat, receiverIdentity: receiverCard.identity)
    }
    
    func test__session_removal__one_session_per_participant__should_delete_session() {
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
        
        Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
        
        try! senderSecureChat.deleteSession(withParticpantIdentity: receiverCard.identity)
        try! receiverSecureChat.deleteSession(withParticpantIdentity: senderCard.identity)
        
        XCTAssert(senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity) == nil)
        XCTAssert(receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity) == nil)
    }
    
    func test__reset__one_session_per_participant__should_reset() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        _ = try! receiverSecureChat.rotateKeys().startSync().getResult()
        _ = try! senderSecureChat.rotateKeys().startSync().getResult()
    
        let senderSession = try! senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().getResult()
        
        let plainText = UUID().uuidString
        let cipherText = try! senderSession.encrypt(string: plainText)
        
        let receiverSession = try! receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
        
        let decryptedMessage = try! receiverSession.decryptString(from: cipherText)
        
        XCTAssert(decryptedMessage == plainText)
        
        Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
        
        try! senderSecureChat.reset().startSync().getResult()
        
        XCTAssert(senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity) == nil)
        XCTAssert(try! senderSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty)
        
        try! senderSecureChat.oneTimeKeysStorage.startInteraction()
        XCTAssert(try! senderSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty)
        try! senderSecureChat.oneTimeKeysStorage.stopInteraction()
        
        // Check that reset haven't affecter receivers
        XCTAssert(receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity) != nil)
    
        try! receiverSecureChat.reset().startSync().getResult()
        
        XCTAssert(receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity) == nil)
        XCTAssert(try! receiverSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty)
        try! receiverSecureChat.oneTimeKeysStorage.startInteraction()
        XCTAssert(try! receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty)
        try! receiverSecureChat.oneTimeKeysStorage.stopInteraction()
    }
}
