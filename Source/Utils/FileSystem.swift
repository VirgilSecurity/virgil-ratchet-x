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

// TODO: Add logging
@objc(VSRFileSystem) open class FileSystem: NSObject {
    @objc public let fileManager = FileManager()
    @objc public let identity: String
    
    @objc public init(identity: String) {
        self.identity = identity
    }
    
    private func createRatchetTempDir() throws -> URL {
        var dirUrl = try self.fileManager.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: try self.createOneTimeKeysUrl(), create: true)
        
        dirUrl.appendPathComponent("VIRGIL-RATCHET")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")
        }
        
        dirUrl.appendPathComponent("\(self.identity)")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")
        }
        
        return dirUrl
    }
    
    private func createRatchetSuppDir() throws -> URL {
        var dirUrl = try self.fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        
        dirUrl.appendPathComponent("VIRGIL-RATCHET")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")
            
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            
            try dirUrl.setResourceValues(values)
        }
        
        dirUrl.appendPathComponent("\(self.identity)")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")
        }
        
        return dirUrl
    }
    
    private func replaceFile(url: URL, data: Data) throws {
        let tempFileUrl = try self.createTempFileUrl()
        
        try? self.fileManager.removeItem(at: tempFileUrl)
        self.fileManager.createFile(atPath: tempFileUrl.path, contents: data, attributes: nil)
        
        try self.fileManager.replaceItem(at: url, withItemAt: tempFileUrl, backupItemName: "BACKUP", options: [], resultingItemURL: nil)
        Log.debug("Replaced \(url.absoluteString) with \(tempFileUrl.absoluteString)")
    }
    
    private func createOneTimeKeysUrl() throws -> URL {
        var url = try self.createRatchetSuppDir()
        
        url.appendPathComponent("OTK")
        
        return url
    }
    
    private func createSessionDir() throws -> URL {
        var dirUrl = try self.createRatchetSuppDir()
        
        dirUrl.appendPathComponent("SESSION")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")
        }
        
        return dirUrl
    }
    
    private func createSessionUrl(identity: String) throws -> URL {
        var url = try self.createSessionDir()
        
        url.appendPathComponent(identity)
        
        return url
    }
    
    @objc open func writeOneTimeKeysFile(data: Data) throws {
        Log.debug("createOneTimeKeysFile")
        
        let url = try self.createOneTimeKeysUrl()
        
        try self.writeFile(url: url, data: data)
    }
    
    @objc open func readOneTimeKeysFile() throws -> Data {
        // TODO: Add encryption
        
        Log.debug("readOneTimeKeysFile")
        
        let url = try self.createOneTimeKeysUrl()
        
        return self.fileManager.contents(atPath: url.path) ?? Data()
    }
    
    private func createTempFileUrl() throws -> URL {
        let dirUrl = try self.createRatchetTempDir()
        
        return dirUrl.appendingPathComponent(NSUUID().uuidString)
    }
    
    @objc open func readSession(identity: String) throws -> Data {
        Log.debug("readSession with \(identity)")
        
        let url = try self.createSessionUrl(identity: identity)
        
        return self.fileManager.contents(atPath: url.path) ?? Data()
    }
    
    private func writeFile(url: URL, data: Data) throws {
        if !self.fileManager.fileExists(atPath: url.path) {
            self.fileManager.createFile(atPath: url.path, contents: data, attributes: nil)
        }
        else {
            try self.replaceFile(url: url, data: data)
        }
    }
    
    @objc open func writeSessionFile(identity: String, data: Data) throws {
        Log.debug("writeSessionFile \(identity)")
        
        let url = try self.createSessionUrl(identity: identity)
        
        try self.writeFile(url: url, data: data)
    }
    
    @objc open func deleteSessionFile(identity: String) throws {
        Log.debug("deleteSessionFile \(identity)")
        
        let url = try self.createSessionUrl(identity: identity)
        
        try self.fileManager.removeItem(at: url)
    }
}
