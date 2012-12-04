------------------------------------------------------------------------
--  SecureMessage.hs
--
--  This module implements a secure-message data structure that
--  incorporates both encrypted data and digital signatures.
------------------------------------------------------------------------

-- KEVIN VECE







module SecureMessage where

--
-- import some crypto packages
--

import Codec.Crypto.RSA as RSA
import Codec.Crypto.AES as AES
import Crypto.Types.PubKey.RSA
import Crypto.PasswordStore
import Crypto.Hash.SHA256
  
import System.Random
import Crypto.Random    -- for CryptoRandomGen type class
import Data.Numbers.Primes

import Data.Char
  --
-- import some ByteString packages
--
--   Note that AES keys and initialization vectors (IV) are 
--       implemented in Codec.Crypto.AES as B.ByteStrings
--
--   However, both AES and RSA (in the Codec.Crypto packages)
--       are able to encrypt/decrypt LB.ByteStrings 
--

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import qualified Codec.Binary.UTF8.String as C

------------------------------------------------------------------------
--  The message data structure
------------------------------------------------------------------------

ivVal :: B.ByteString
ivVal = B.pack [67,43,12,98,241,235,211,167, 94,61,13,91,23,25,234,107]

data Message = Msg { from :: String,    -- "From:" field
                     to :: String,      -- "To:" field
                     contents :: LB.ByteString,  -- encrypted contents
                     encDEK :: LB.ByteString,     -- encrypted DEK
                     iv :: B.ByteString, -- initialization vector
                     digSig :: LB.ByteString   -- digital signature
                    }
               deriving (Read, Show)

data Payload = AuthTunnel1 { username :: String,
                             challengeText :: LB.ByteString
                          } |
               AuthTunnel2 { challengeText :: LB.ByteString,
                             challengeResponse :: Char
                          } |
               AuthTunnel3 { challengeResponse :: Char
                          } |
               AuthTunnel4 { seed :: LB.ByteString
                          } |
               AuthTunnel5 { seed :: LB.ByteString,
                             keyCheck :: LB.ByteString
                          } |
               AuthTunnel6 { keyCheck :: LB.ByteString
                          } |
               AuthTunnel7 { pN :: Integer,
                             gN :: Integer,
                             gAmodP :: Integer
                          } |
               AuthTunnel8 { gBmodP :: Integer
                          } |
               EncrMsg { encrContents :: LB.ByteString
                   } |
               Status { linkMsg :: Int
                        }
               deriving (Read, Show)

type EncrPayload = LB.ByteString

data Packet = Probe { senderKey :: PublicKey,
                      senderPort :: Int
                    } |
              Link { value :: EncrPayload,
                     signature :: LB.ByteString
                   }
              deriving (Read, Show)
              
sendProbe :: RandomGen g => CryptoRandomGen h => g -> h -> (Packet, PrivateKey, Int,  g, h)
sendProbe g h = let (pubK, priK, h') = RSA.generateKeyPair h 2048
                    (portNum, g') = randomR (1025,65553) g
                    in
                 (Probe pubK portNum, priK, portNum, g', h')
                 
respondProbe :: RandomGen g => CryptoRandomGen h => g -> h -> Int -> (Packet, PrivateKey, g, h)
respondProbe g h portNum = let (pubK, priK, h') = RSA.generateKeyPair h 2058
                       in
                    (Probe pubK portNum, priK, g, h')
                       
hashPassword :: String -> LB.ByteString
hashPassword pass = let words = C.encode pass
                        bytestring = LB.pack words
                    in
                     LB.fromChunks [hashlazy bytestring]
                    
makeLinkPacket :: RandomGen g => CryptoRandomGen h => g -> h -> Int -> Payload -> PrivateKey -> PublicKey-> (Packet, g, h)
makeLinkPacket g h linkType info priK pubK= let payloadString = (show linkType) ++ (show info)
                                                payloadWords = C.encode payloadString
                                                payloadByteString = LB.pack payloadWords
                                                (encrPayload, h') = RSA.encrypt h pubK payloadByteString
                                            in
                                             (Link encrPayload (RSA.sign priK encrPayload), g, h')

readLinkPacket :: Packet -> PrivateKey -> PublicKey -> Maybe (LB.ByteString)
readLinkPacket (Link info sig) privK pubK = let decrPayload = RSA.decrypt privK info
                                                isValid = RSA.verify pubK info sig
                                            in
                                             if isValid then
                                               Just decrPayload
                                             else
                                               Nothing
                                                               

linkType packet = C.decode $ [LB.head packet]

linkValue packet = concat $ map C.decode $ [LB.unpack $ LB.tail packet]

genCT :: RandomGen g => CryptoRandomGen h => g -> h -> (LB.ByteString, g, h)
genCT g h = let (Right (num, h')) = genBytes 8 h
            in
             (LB.fromChunks [num], g, h')
             
genCR :: LB.ByteString -> PublicKey -> LB.ByteString -> Int -> Char
genCR ct sendPubKey hashedPassword num = let text = (show sendPubKey) ++ (show hashedPassword)
                                             textWords = C.encode text
                                             textByteString = LB.pack textWords
                                             salt = makeSalt (B.concat $ LB.toChunks textByteString)
                                             bytes = LB.fromChunks [makePasswordSalt (B.concat $ LB.toChunks ct) salt num]
                                         in
                                          (show bytes) !! (48 + num)

verifyCR :: LB.ByteString -> Char -> PublicKey -> LB.ByteString -> Int-> Bool
verifyCR ct cr sendPubKey hashedPassword num = let verification = genCR ct sendPubKey hashedPassword num
                                               in
                                                cr == verification

                                                
genSeed :: RandomGen g => CryptoRandomGen h => g -> h -> (LB.ByteString, g, h)
genSeed g h = let (Right (num, h')) = genBytes 128 h
              in
               (LB.fromChunks [num], g, h')
               
kvf :: LB.ByteString -> LB.ByteString -> PublicKey -> LB.ByteString-> LB.ByteString
kvf seed1 seed2 sendPubKey passwordHash = let text = (show sendPubKey) ++ (show passwordHash)
                                              textWords = C.encode text
                                              textByteString = LB.pack textWords
                                              salt = makeSalt (B.concat $ LB.toChunks textByteString)
                                              info = LB.concat [seed1, seed2]
                                              bytes = LB.fromChunks [makePasswordSalt (B.concat $ LB.toChunks info) salt 12]
                                          in
                                           LB.fromChunks [hashlazy bytes]

                                       
verifyKVF :: LB.ByteString -> LB.ByteString -> LB.ByteString -> PublicKey -> LB.ByteString-> Bool
verifyKVF result seed1 seed2 sendPubKey passwordHash = let verification = kvf seed1 seed2 sendPubKey passwordHash
                                                       in
                                                        result == verification

genPrime :: RandomGen g => CryptoRandomGen h => g -> h -> (Integer, g, h)
genPrime g h = let (which, g') = (randomR (10000,100000) g)
               in
                (primes !! which, g', h)
                
genNum :: RandomGen g => CryptoRandomGen h => g -> h -> (Integer, g, h)
genNum g h = let (num, g') = randomR (10,99999) g                        
             in
              (num,g',h)

genSessionKey :: Integer -> LB.ByteString
genSessionKey i = let text = make16 $ show i
                      textWords = C.encode text
                  in
                   LB.pack textWords

make16 :: String -> String
make16 str = if length str == 16 then
               str
             else
               make16 ('0':str)

genMsg :: LB.ByteString -> String -> Payload
genMsg key msg = let msgByteString =  LB.pack $ C.encode msg
                            in
                             EncrMsg (AES.crypt CTR (B.concat $ LB.toChunks key) ivVal Encrypt msgByteString)
                             
readMsg :: LB.ByteString -> Payload -> String
readMsg key (EncrMsg encr) = let bytes = AES.crypt CTR (B.concat $ LB.toChunks key) ivVal Decrypt encr
                             in
                              concat $ map C.decode $ [LB.unpack bytes]
--
--   createMsg gen sender receiver sendPrivKey recPubKey dek iv plaintext 
--
--      Creates a secure message with following fields:
--            from: sender
--            to: receiver
--            contents: AES encryption (using dek and iv) of plaintext
--            encDEK: RSA encryption of dek
--            iv: initialization vector (for AES), sent in the clear
--            digSig: RSA digital signature of plaintext
--

createMsg :: CryptoRandomGen g =>  
             g -> String ->  String -> PrivateKey -> PublicKey 
               -> B.ByteString -> B.ByteString -> LB.ByteString 
               -> (Message, g)

createMsg gen sender receiver sendPrivKey recPubKey dek iv plaintext = 
  (Msg {from = sender, to = receiver, contents = encrContents, encDEK = encrDEK, iv = iv, digSig = sig}, g)
  where encrContents = AES.crypt (CTR) (dek) (iv) (Encrypt) plaintext
        (encrDEK, g) = RSA.encrypt gen recPubKey (LB.fromChunks [dek])
        sig = RSA.sign sendPrivKey plaintext



                 


--
--   decodeMsg recPrivKey sendPubKey msg
--
--       Decodes and integrity checks a secure message
--

decodeMsg :: PrivateKey -> PublicKey -> Message -> (LB.ByteString,Bool)
decodeMsg recPrivKey sendPubKey (Msg from to contents encDEK iv digSig) =
  (plaintext, check)
  where dek = RSA.decrypt recPrivKey (encDEK)
        plaintext = AES.crypt (CTR) (B.concat $ LB.toChunks dek) (iv) (Decrypt) contents
        check = RSA.verify sendPubKey plaintext digSig
        
