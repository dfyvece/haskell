------------------------------------------------------------------------
--  hw5tester.hs
--
--     A wrapper for HW 5, to test the code in SecureMessage
------------------------------------------------------------------------

import SecureMessage

import System.IO

import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString as B
import qualified Codec.Binary.UTF8.String as C
  
import Crypto.Types.PubKey.RSA  -- for public/private keys
import Crypto.Random  -- used purely for newGenIO 
import Crypto.Hash.SHA256

import System.Random
import System.Time

import Network.Socket
import qualified Network.Socket.ByteString.Lazy as LSock
import Control.Monad  
import Control.Concurrent
  
import Data.Word

                          
main :: IO ()                          
main = withSocketsDo $
         do putStr ("Enter IP address to connect to: ")
            hFlush stdout
            addr <- getLine
            putStr ("Enter server port number: ")
            hFlush stdout
            portnum <- getLine
            putStr ("Enter password: ")
            hFlush stdout
            password <- getLine
            
            let hints = defaultHints { addrFlags = [AI_PASSIVE, AI_ADDRCONFIG] }
            addrinfos <- getAddrInfo (Just hints) (Just addr) (Just portnum)
            let serveraddr = head addrinfos
            sock <- socket (addrFamily serveraddr) Stream defaultProtocol
            setSocketOption sock ReuseAddr 1
            connect sock (addrAddress serveraddr)
            timer <- getClockTime
            let (CalendarTime _ _ _ _ _ _ pico _ _ _ _ _) = toUTCTime timer
            let epochSeconds = fromIntegral pico
            g <- return (mkStdGen epochSeconds)
            h <- newGenIO :: IO SystemRandom

            -- PROBE PHASE
            let (probe1,sendPrivKey,port,g',h') = sendProbe g h
            let sendPubKey = senderKey probe1
            send sock $ show probe1

            probe2 <- recv sock 4096
            let probe2pack = read probe2 :: Packet
            let recPubKey = senderKey probe2pack
            
            -- ID PHASE
            let username = "Alice"
            let hashedPassword = hashPassword password
            let (serverCT, g'',h'') = genCT g' h'
            let id1 = AuthTunnel1 username serverCT
            let (id1pack,g''',h''') = makeLinkPacket g'' h'' 0 id1 sendPrivKey recPubKey
            send sock $ show id1pack
            
            id2 <- recv sock 4096
            let id2pack = read id2 :: Packet
            let (Just id2info) =  readLinkPacket id2pack sendPrivKey recPubKey
            let id2dec = read $ linkValue id2info :: Payload
            let clientCT = challengeText id2dec
            if (not $ verifyCR serverCT (challengeResponse id2dec) recPubKey hashedPassword 0)
            then
              sClose sock
            else
              putStr (".")
            hFlush stdout

            let id3 = AuthTunnel3 (genCR clientCT sendPubKey hashedPassword 0)
            let (id3pack, g'''', h'''') = makeLinkPacket g''' h''' 0 id3 sendPrivKey recPubKey
            send sock $ show id3pack

            id4 <- recv sock 4096
            let id4pack = read id4 :: Packet
            let (Just id4info) = readLinkPacket id4pack sendPrivKey recPubKey
            let id4dec = read $ linkValue id4info :: Payload
            if (not $ verifyCR serverCT (challengeResponse id4dec) recPubKey hashedPassword 1)
            then
              sClose sock
            else
              putStr (".")
            hFlush stdout

            let id5 = AuthTunnel3 (genCR clientCT sendPubKey hashedPassword 1)
            let (id5pack, g''''', h''''') = makeLinkPacket g'''' h'''' 0 id5 sendPrivKey recPubKey
            send sock $ show id5pack

            -- VERIFICATION PHASE
            ver1 <- recv sock 4096
            let ver1pack = read ver1 :: Packet
            let (Just ver1info) =  readLinkPacket ver1pack sendPrivKey recPubKey
            let ver1dec = read $ linkValue ver1info :: Payload
            let seed1 = seed ver1dec

            let (seed2, g2, h2) = genSeed g''''' h'''''
            let cliKeyCheck = kvf seed1 seed2 recPubKey hashedPassword
            let ver2 = AuthTunnel5 seed2 cliKeyCheck
            let (ver2pack, g2', h2') = makeLinkPacket g2 h2 0 ver2 sendPrivKey recPubKey
            send sock $ show ver2pack

            ver3 <- recv sock 4096
            let ver3pack = read ver3 :: Packet
            let (Just ver3info) =  readLinkPacket ver3pack sendPrivKey recPubKey
            let ver3dec = read $ linkValue ver3info :: Payload
            let result = keyCheck ver3dec
            if (not $ verifyKVF result seed2 seed1 sendPubKey hashedPassword)
            then
              sClose sock
            else
              putStr (".")
            hFlush stdout

            -- SESSION KEY GENERATION PHASE
            let (pNum, g2'', h2'') = genPrime g2' h2'
            let (gNum, g2''', h2''') = genNum g2'' h2''
            let (aNum, g2'''', h2'''') = genNum g2''' h2'''
            let gAP = (gNum ^ aNum) `mod` pNum
            let diff1 = AuthTunnel7 pNum gNum gAP
            let (diff1pack, g2''''', h2''''') = makeLinkPacket g2'''' h2'''' 0 diff1 sendPrivKey recPubKey
            send sock $ show diff1pack

            diff2 <- recv sock 4096
            let diff2pack = read diff2 :: Packet
            let (Just diff2info) =  readLinkPacket diff2pack sendPrivKey recPubKey
            let diff2dec = read $ linkValue diff2info :: Payload
            let gBP = gBmodP diff2dec
            let sessionKey = (gBP ^ aNum) `mod` pNum
            let sk = genSessionKey sessionKey
            putStrLn ("Connected!")
            hFlush stdout

            forkIO $ readSock g2''''' h2''''' sock sendPrivKey recPubKey sk
            writeSock g2''''' h2''''' sock sendPrivKey recPubKey sk
--            runnSock g2''''' h2''''' sock sendPrivKey recPubKey sk
            sClose sock


runnSock :: RandomGen a => CryptoRandomGen b => a -> b -> Socket -> PrivateKey -> PublicKey -> LB.ByteString -> IO ()
runnSock g h sock privK pubK sk = do putStr("> ")
                                     hFlush stdout
                                     newmsg <- getLine
                                     let msg = genMsg sk newmsg
                                     let (msgpack, g', h') = makeLinkPacket g h 0 msg privK pubK
                                     send sock $ show msgpack
                                     msg <- recv sock 4096
                                     let msgpack = read msg :: Packet
                                     let (Just val) = readLinkPacket msgpack privK pubK
                                     let uncr = linkValue val
                                     let inf = read uncr :: Payload
                                     putStrLn ("< " ++ (show $ readMsg sk inf))
                                     runnSock g' h' sock privK pubK sk

readSock :: RandomGen a => CryptoRandomGen b => a -> b -> Socket -> PrivateKey -> PublicKey -> LB.ByteString -> IO ()
readSock g h sock privK pubK sk = do newmsg <- getLine
                                     let msg = genMsg sk newmsg
                                     let (msgpack, g', h') = makeLinkPacket g h 0 msg privK pubK
                                     send sock $ show msgpack
                                     readSock g h sock privK pubK sk
                                     
writeSock :: RandomGen a => CryptoRandomGen b => a -> b -> Socket -> PrivateKey -> PublicKey -> LB.ByteString -> IO ()
writeSock g h sock privK pubK sk = do msg <- recv sock 4096
                                      let msgpack = read msg :: Packet
                                      let (Just val) = readLinkPacket msgpack privK pubK
                                      let uncr = linkValue val
                                      let inf = read uncr :: Payload
                                      putStrLn ("> " ++ (show $ readMsg sk inf))
                                      hFlush stdout
                                      writeSock g h sock privK pubK sk

runnConn :: RandomGen a => CryptoRandomGen b => a -> b -> Socket -> PrivateKey -> PublicKey -> LB.ByteString -> IO ()
runnConn g h sock privK pubK sk = do msg <- recv sock 4096
                                     let msgpack = read msg :: Packet
                                     let (Just val) = readLinkPacket msgpack privK pubK
                                     let uncr = linkValue val
                                     let inf = read uncr :: Payload
                                     putStrLn ("< " ++ (show $ readMsg sk inf))
                                     putStr ("> ")
                                     newmsg <- getLine
                                     let msg = genMsg sk newmsg
                                     let (msgpack, g', h') = makeLinkPacket g h 0 msg privK pubK
                                     send sock $ show msgpack
                                     runnConn g' h' sock privK pubK sk