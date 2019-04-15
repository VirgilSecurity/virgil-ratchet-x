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
    
    private func initChat() -> (Card, Card, SecureChat, SecureChat) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        let receiverIdentityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        let senderIdentityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        
        let senderIdentity = NSUUID().uuidString
        let receiverIdentity = NSUUID().uuidString
        
        let receiverTokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(virgilCrypto: crypto), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: receiverIdentity), nil)
        })
        
        let senderTokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(virgilCrypto: crypto), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: senderIdentity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto))!
        cardVerifier.verifyVirgilSignature = false
        
        let senderCardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto), accessTokenProvider: senderTokenProvider, cardVerifier: cardVerifier)
        let receiverCardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto), accessTokenProvider: receiverTokenProvider, cardVerifier: cardVerifier)
        senderCardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        receiverCardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let senderCardManager = CardManager(params: senderCardManagerParams)
        let receiverCardManager = CardManager(params: receiverCardManagerParams)
        
        let receiverCard = try! receiverCardManager.publishCard(privateKey: receiverIdentityKeyPair.privateKey, publicKey: receiverIdentityKeyPair.publicKey).startSync().getResult()
        let senderCard = try! senderCardManager.publishCard(privateKey: senderIdentityKeyPair.privateKey, publicKey: senderIdentityKeyPair.publicKey).startSync().getResult()
        
        let params = try! KeychainStorageParams.makeKeychainStorageParams(appName: "test")
        let receiverLongTermKeysStorage = try! KeychainLongTermKeysStorage(identity: receiverIdentity, params: params)
        let senderLongTermKeysStorage = try! KeychainLongTermKeysStorage(identity: senderIdentity, params: params)
        
        let receiverOneTimeKeysStorage = FileOneTimeKeysStorage(identity: receiverIdentity)
        let senderOneTimeKeysStorage = FileOneTimeKeysStorage(identity: senderIdentity)

        let client = RatchetClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let receiverKeysRotator = KeysRotator(crypto: crypto, identityPrivateKey: receiverIdentityKeyPair.privateKey, identityCardId: receiverCard.identifier, orphanedOneTimeKeyTtl: 5, longTermKeyTtl: 10, outdatedLongTermKeyTtl: 5, desiredNumberOfOneTimeKeys: IntegrationTests.desiredNumberOfOtKeys, longTermKeysStorage: receiverLongTermKeysStorage, oneTimeKeysStorage: receiverOneTimeKeysStorage, client: client)
        
        let senderKeysRotator = KeysRotator(crypto: crypto, identityPrivateKey: senderIdentityKeyPair.privateKey, identityCardId: senderCard.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: IntegrationTests.desiredNumberOfOtKeys, longTermKeysStorage: senderLongTermKeysStorage, oneTimeKeysStorage: senderOneTimeKeysStorage, client: client)
        
        
        let senderSecureChat = SecureChat(crypto: crypto,
                                          identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          identityCard: senderCard,
                                          accessTokenProvider: senderTokenProvider,
                                          client: client,
                                          longTermKeysStorage: senderLongTermKeysStorage,
                                          oneTimeKeysStorage: senderOneTimeKeysStorage,
                                          sessionStorage: FileSessionStorage(identity: senderIdentity, crypto: crypto),
                                          groupSessionStorage: FileGroupSessionStorage(identity: senderIdentity, crypto: crypto),
                                          keysRotator: senderKeysRotator)
        
        let receiverSecureChat = SecureChat(crypto: crypto,
                                            identityPrivateKey: receiverIdentityKeyPair.privateKey,
                                            identityCard: receiverCard,
                                            accessTokenProvider: receiverTokenProvider,
                                            client: client,
                                            longTermKeysStorage: receiverLongTermKeysStorage,
                                            oneTimeKeysStorage: receiverOneTimeKeysStorage,
                                            sessionStorage: FileSessionStorage(identity: receiverIdentity, crypto: crypto),
                                            groupSessionStorage: FileGroupSessionStorage(identity: receiverIdentity, crypto: crypto),
                                            keysRotator: receiverKeysRotator)
        
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }
    
    func test1__encrypt_decrypt__random_uuid_messages__should_decrypt() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        let initMsg = try! senderSecureChat.startNewGroupSession(with: [receiverCard])
        
        let senderSession = try! senderSecureChat.startGroupSession(with: [senderCard], using: initMsg)
        let receiverSession = try! receiverSecureChat.startGroupSession(with: [receiverCard], using: initMsg)
        
        Utils.encryptDecrypt100Times(senderGroupSession: senderSession, receiverGroupSession: receiverSession)
    }
}
