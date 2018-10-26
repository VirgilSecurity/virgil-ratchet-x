//
//  SessionStorage.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/24/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

@objc(VSRSessionStorage) public protocol SessionStorage: class {
    @objc func storeSession(_ session: SecureSession) throws
    @objc func retrieveSession(participantIdentity: String) -> SecureSession?
    @objc func deleteSession(participantIdentity: String) throws
}
