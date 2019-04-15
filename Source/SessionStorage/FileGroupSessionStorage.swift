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

import Foundation
import VirgilCrypto

/// FileSessionStorage using files
/// This class is thread-safe
@objc(VSRFileGroupSessionStorage) open class FileGroupSessionStorage: NSObject, GroupSessionStorage {
    private let fileSystem: FileSystem
    private let queue = DispatchQueue(label: "FileGroupSessionStorageQueue")
    private let crypto: VirgilCrypto
    
    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: identity of this user
    ///   - crypto: VirgilCrypto that will be forwarded to SecureSession
    @objc public init(identity: String, crypto: VirgilCrypto) {
        self.fileSystem = FileSystem(userIdentifier: identity, pathComponents: ["GROUPS"])
        self.crypto = crypto
        
        super.init()
    }
    
    /// Stores session
    ///
    /// - Parameter session: session to store
    /// - Throws: Rethrows from FileSystem
    public func storeSession(_ session: SecureGroupSession) throws {
        try self.queue.sync {
            let data = session.serialize()
            
            try self.fileSystem.write(data: data, name: session.identifier)
        }
    }
    
    /// Retrieves session
    ///
    /// - Parameter participantIdentity: participant identity
    /// - Throws: Rethrows from FileSystem
    public func retrieveSession(identifier: String, privateKeyData: Data) -> SecureGroupSession? {
        guard let data = try? self.fileSystem.read(name: identifier), !data.isEmpty else {
            return nil
        }
        
        return try? SecureGroupSession(data: data,
                                       privateKeyData: privateKeyData,
                                       sessionStorage: self,
                                       crypto: self.crypto)
    }
    
    /// Deletes session
    ///
    /// - Parameter participantIdentity: participantIdentity: participant identity
    /// - Throws: Rethrows from FileSystem
    public func deleteSession(identifier: String) throws {
        try self.queue.sync {
            try self.fileSystem.delete(name: identifier)
        }
    }
    
    /// Removes all sessions
    ///
    /// - Throws: Rethrows from FileSystem
    public func reset() throws {
        try self.queue.sync {
            try self.fileSystem.delete()
        }
    }
}
