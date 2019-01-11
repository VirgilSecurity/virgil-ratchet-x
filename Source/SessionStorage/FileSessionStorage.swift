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

@objc(VSRFileSessionStorage) open class FileSessionStorage: NSObject, SessionStorage {
    private let fileSystem: FileSystem
    
    @objc convenience init(identity: String) {
        let fileSystem = FileSystem(identity: identity)
        
        self.init(fileSystem: fileSystem)
    }
    
    @objc public init(fileSystem: FileSystem) {
        self.fileSystem = fileSystem
        
        super.init()
    }
    
    public func storeSession(_ session: SecureSession) throws {
        let data = session.serialize()

        try self.fileSystem.writeSessionFile(identity: session.participantIdentity, data: data)
    }
    
    public func retrieveSession(participantIdentity: String) -> SecureSession? {
        guard let data = try? self.fileSystem.readSession(identity: participantIdentity), !data.isEmpty else {
            return nil
        }
        
        return try? SecureSession(data: data, participantIdentity: participantIdentity, sessionStorage: self)
    }
    
    public func deleteSession(participantIdentity: String) throws {
        try self.fileSystem.deleteSessionFile(identity: participantIdentity)
    }
}
