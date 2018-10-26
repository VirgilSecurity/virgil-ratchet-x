//
//  Stubs.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/24/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCryptoApiImpl
@testable import VirgilSDKRatchet

class FakeRamSessionStorage: SessionStorage {
    private var db: [String: SecureSession] = [:]
    
    func storeSession(_ session: SecureSession) throws {
        self.db[session.participantIdentity] = session
    }
    
    func retrieveSession(participantIdentity: String) -> SecureSession? {
        return self.db[participantIdentity]
    }
    
    func deleteSession(participantIdentity: String) throws {
        guard self.db.removeValue(forKey: participantIdentity) != nil else {
            throw NSError()
        }
    }
}

class FakePrivateKeyProvider: PrivateKeyProvider {
    let db: [Data: Data]
    
    init(db: [Data: Data]) {
        self.db = db
    }
    
    func getPrivateKey(withId id: Data) throws -> Data {
        guard let val = self.db[id] else {
            throw NSError()
        }
        
        return val
    }
}

class FakeClient: RatchetClientProtocol {
    let publicKeySet: PublicKeySet
    
    init(publicKeySet: PublicKeySet) {
        self.publicKeySet = publicKeySet
    }
    
    func uploadPublicKeys(identityCardId: String?, longtermPublicKey: SignedPublicKey?, onetimePublicKeys: [Data]?, token: String) throws {
        
    }
    
    func getNumberOfActiveOneTimePublicKeys(token: String) throws -> Int {
        return 0
    }
    
    func validatePublicKeys(longTermKeyId: Data, oneTimeKeysIds: [Data], token: String) throws -> ValidatePublicKeysResponse {
        return try JSONDecoder().decode(ValidatePublicKeysResponse.self, from: Data())
    }
    
    func getPublicKeySet(forRecipientIdentity identity: String, token: String) throws -> PublicKeySet {
        return publicKeySet
    }
}

class FakeRamClient: RatchetClientProtocol {
    struct UserStore {
        var identityPublicKey: (VirgilPublicKey, Data)?
        var longtermPublicKey: SignedPublicKey?
        var usedLongtermPublicKeys: Set<SignedPublicKey> = []
        var onetimePublicKeys: Set<Data> = []
        var usedOnetimePublicKeys: Set<Data> = []
    }
    
    private let cardManager: CardManager
    private let crypto = VirgilCrypto()
    private var users: [String: UserStore] = [:]
    
    init(cardManager: CardManager) {
        self.cardManager = cardManager
    }
    
    func uploadPublicKeys(identityCardId: String?, longtermPublicKey: SignedPublicKey?, onetimePublicKeys: [Data]?, token: String) throws {
        guard let jwt = try? Jwt(stringRepresentation: token) else {
            throw NSError()
        }
        
        var userStore = self.users[jwt.identity()] ?? UserStore()
        
        let publicKey: VirgilPublicKey
        if let identityCardId = identityCardId {
            let card = try self.cardManager.getCard(withId: identityCardId).startSync().getResult()
            publicKey = card.publicKey as! VirgilPublicKey
            userStore.identityPublicKey = (publicKey, CUtils.extractRawPublicKey(self.crypto.exportPublicKey(publicKey)))
        }
        else {
            guard let existingIdentityPublicKey = userStore.identityPublicKey else {
                throw NSError()
            }
            
            publicKey = existingIdentityPublicKey.0
        }
        
        if let longtermPublicKey = longtermPublicKey {
            guard crypto.verifySignature(longtermPublicKey.signature, of: longtermPublicKey.publicKey, with: publicKey) else {
                throw NSError()
            }

            if let usedLongTermPublicKey = userStore.longtermPublicKey {
                userStore.usedLongtermPublicKeys.insert(usedLongTermPublicKey)
            }
            
            userStore.longtermPublicKey = longtermPublicKey
        }
        else {
            guard userStore.longtermPublicKey != nil else {
                throw NSError()
            }
        }
        
        if let onetimePublicKeys = onetimePublicKeys {
            let newKeysSet = Set<Data>(onetimePublicKeys)
            
            guard userStore.onetimePublicKeys.intersection(newKeysSet).isEmpty else {
                throw NSError()
            }
            
            userStore.onetimePublicKeys.formUnion(newKeysSet)
        }
        
        self.users[jwt.identity()] = userStore
    }
    
    func getNumberOfActiveOneTimePublicKeys(token: String) throws -> Int {
        guard let jwt = try? Jwt(stringRepresentation: token) else {
            throw NSError()
        }
        
        let userStore = self.users[jwt.identity()] ?? UserStore()
        
        return userStore.onetimePublicKeys.count
    }
    
    func validatePublicKeys(longTermKeyId: Data, oneTimeKeysIds: [Data], token: String) throws -> ValidatePublicKeysResponse {
        guard let jwt = try? Jwt(stringRepresentation: token) else {
            throw NSError()
        }
        
        let userStore = self.users[jwt.identity()] ?? UserStore()
        
        let usedLongTermKeyId: Data?
        
        if let longtermPublicKey = userStore.longtermPublicKey?.publicKey {
            let hash = self.crypto.computeHash(for: longtermPublicKey, using: .SHA512).subdata(in: 0..<8)
            
            usedLongTermKeyId = hash == longTermKeyId ? nil : longTermKeyId
        }
        else {
            usedLongTermKeyId = nil
        }
        
        let usedOneTimeKeysIds: [Data] = Array<Data>(Set<Data>(userStore.usedOnetimePublicKeys.map {
                return self.crypto.computeHash(for: $0, using: .SHA512).subdata(in: 0..<8)
            }).intersection(Set<Data>(oneTimeKeysIds)))
        
        return ValidatePublicKeysResponse(usedLongTermKeyId: usedLongTermKeyId, usedOneTimeKeysIds: usedOneTimeKeysIds)
    }
    
    func getPublicKeySet(forRecipientIdentity identity: String, token: String) throws -> PublicKeySet {
        guard let jwt = try? Jwt(stringRepresentation: token) else {
            throw NSError()
        }
        
        var userStore = self.users[jwt.identity()] ?? UserStore()
        
        guard let identityPublicKey = userStore.identityPublicKey?.1,
            let longTermPublicKey = userStore.longtermPublicKey else {
                throw NSError()
        }
        
        let oneTimePublicKey: Data?
        if let randomOneTimePublicKey = userStore.onetimePublicKeys.randomElement() {
            oneTimePublicKey = randomOneTimePublicKey
            userStore.onetimePublicKeys.remove(randomOneTimePublicKey)
            
            self.users[jwt.identity()] = userStore
        }
        else {
            oneTimePublicKey = nil
        }
        
        return PublicKeySet(identityPublicKey: identityPublicKey, longtermPublicKey: longTermPublicKey, onetimePublicKey: oneTimePublicKey)
    }
}
