// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Opaque device-bound representation, never a raw private key. Called only
// in-process by the protected native host; no command line or IPC endpoint.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

private final class EnclaveKey {
 let key: SecureEnclave.P256.Signing.PrivateKey
 init(_ value:SecureEnclave.P256.Signing.PrivateKey){key=value}
}
private func box(_ pointer:UnsafeMutableRawPointer)->EnclaveKey {
 Unmanaged<EnclaveKey>.fromOpaque(pointer).takeUnretainedValue()
}
private func copy(_ data:Data,_ output:UnsafeMutablePointer<UInt8>?,_ capacity:Int)->Int {
 guard let output=output else{return data.count}
 guard capacity>=data.count else{return -1}
 data.copyBytes(to:output,count:data.count);return data.count
}
@_cdecl("axr_enclave_create")
public func create(_ presence:Int32,_ bytes:UnsafePointer<UInt8>?,_ count:Int)->UnsafeMutableRawPointer? {
 guard SecureEnclave.isAvailable,count>=0,count<=4096 else{return nil}
 do {
  let context=LAContext()
  let key:SecureEnclave.P256.Signing.PrivateKey
  if let bytes=bytes,count>0 {
   key=try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:Data(bytes:bytes,count:count),authenticationContext:context)
  }else{
   var error:Unmanaged<CFError>?
   var flags:SecAccessControlCreateFlags=[.privateKeyUsage]
   if presence != 0 {flags.insert(.userPresence)}
   guard let control=SecAccessControlCreateWithFlags(nil,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,flags,&error) else{return nil}
   key=try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable:false,accessControl:control,authenticationContext:context)
  }
  return Unmanaged.passRetained(EnclaveKey(key)).toOpaque()
 }catch{return nil}
}
@_cdecl("axr_enclave_release")
public func release(_ pointer:UnsafeMutableRawPointer){Unmanaged<EnclaveKey>.fromOpaque(pointer).release()}
@_cdecl("axr_enclave_representation")
public func representation(_ pointer:UnsafeMutableRawPointer,_ output:UnsafeMutablePointer<UInt8>?,_ capacity:Int)->Int {
 copy(box(pointer).key.dataRepresentation,output,capacity)
}
@_cdecl("axr_enclave_public")
public func publicKey(_ pointer:UnsafeMutableRawPointer,_ output:UnsafeMutablePointer<UInt8>?,_ capacity:Int)->Int {
 copy(box(pointer).key.publicKey.x963Representation,output,capacity)
}
@_cdecl("axr_enclave_sign")
public func sign(_ pointer:UnsafeMutableRawPointer,_ bytes:UnsafePointer<UInt8>,_ count:Int,_ output:UnsafeMutablePointer<UInt8>,_ capacity:Int)->Int {
 guard count>=0,count<=1024*1024 else{return -1}
 do{return copy(try box(pointer).key.signature(for:Data(bytes:bytes,count:count)).derRepresentation,output,capacity)}catch{return -1}
}
