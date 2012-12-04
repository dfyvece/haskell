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
         do timer <- getClockTime
            let (CalendarTime _ _ _ _ _ _ pico _ _ _ _ _) = toUTCTime timer
            let epochSeconds = fromIntegral pico
            g <- return (mkStdGen epochSeconds)
            h <- newGenIO :: IO SystemRandom

            putStr ("Enter server IP address: ")
            hFlush stdout
            addr <- getLine
            putStr ("Enter server port: ")
            hFlush stdout
            portnum <- getLine
            putStr ("Enter password: ")
            hFlush stdout
            password <- getLine
            let hashedPassword = hashPassword password
            
            let hints = defaultHints { addrFlags = [AI_PASSIVE, AI_ADDRCONFIG] }
            addrinfos <- getAddrInfo (Just hints) (Just addr) (Just portnum)
            let serveraddr = head addrinfos
            sock <- socket (addrFamily serveraddr) Stream defaultProtocol
            setSocketOption sock ReuseAddr 1
            bindSocket sock (addrAddress serveraddr)
            listen sock 2
            (conn, _) <- accept sock

            -- PROBE PHASE
            probe1 <- recv conn 4096
            let probe1pack = read probe1 :: Packet
            let sendPubKey = senderKey probe1pack
            let port = senderPort probe1pack
            
            let (probe2,recPrivKey,g',h') = respondProbe g h port
            let recPubKey = senderKey probe2
            send conn $ show probe2
            
            -- ID PHASE
            id1 <- recv conn 4096
            let id1pack = read id1 :: Packet
            let (Just id1info) = readLinkPacket id1pack recPrivKey sendPubKey
            let id1dec = read $ linkValue id1info :: Payload
            let serverCT = challengeText id1dec

            let (clientCT, g'', h'') = genCT g' h' 
            let id2 = AuthTunnel2 clientCT (genCR serverCT recPubKey hashedPassword 0)
            let (id2pack, g''', h''') = makeLinkPacket g'' h'' 0 id2 recPrivKey sendPubKey
            send conn $ show id2pack
            
            id3 <- recv conn 4096
            let id3pack = read id3 :: Packet
            let (Just id3info) = readLinkPacket id3pack recPrivKey sendPubKey
            let id3dec = read $ linkValue id3info :: Payload
            if (not $ verifyCR clientCT (challengeResponse id3dec) sendPubKey hashedPassword 0)
            then
              sClose sock
            else
              putStr (".")
            hFlush stdout

            let id4 = AuthTunnel3 (genCR serverCT recPubKey hashedPassword 1)
            let (id4pack, g'''', h'''') = makeLinkPacket g''' h''' 0 id4 recPrivKey sendPubKey
            send conn $ show id4pack

            id5 <- recv conn 4096
            let id5pack = read id5 :: Packet
            let (Just id5info) = readLinkPacket id5pack recPrivKey sendPubKey
            let id5dec = read $ linkValue id5info :: Payload
            if (not $ verifyCR clientCT (challengeResponse id5dec) sendPubKey hashedPassword 1)
            then
              sClose sock
            else
              putStr (".")
            hFlush stdout

            -- VERIFICATION PHASE
            let (seed1, g''''', h''''') = genSeed g'''' h''''
            let ver1 = AuthTunnel4 seed1
            let (ver1pack, g2, h2) = makeLinkPacket g''''' h''''' 0 ver1 recPrivKey sendPubKey
            send conn $ show ver1pack

            ver2 <- recv conn 4096
            let ver2pack = read ver2 :: Packet
            let (Just ver2info) = readLinkPacket ver2pack recPrivKey sendPubKey
            let ver2dec = read $ linkValue ver2info :: Payload
            let seed2 = seed ver2dec
            let result = keyCheck ver2dec
            if (not $ verifyKVF result seed1 seed2 recPubKey hashedPassword)
            then
              sClose sock
            else
              putStr (".")
            hFlush stdout

            let recKeyCheck = kvf seed2 seed1 sendPubKey hashedPassword
            let ver3 = AuthTunnel6 recKeyCheck
            let (ver3pack, g2', h2') = makeLinkPacket g2 h2 0 ver3 recPrivKey sendPubKey
            send conn $ show ver3pack

            -- SESSION KEY GENERATION PHASE
            diff1 <- recv conn 4096
            let diff1pack = read diff1 :: Packet
            let (Just diff1info) = readLinkPacket diff1pack recPrivKey sendPubKey
            let diff1dec = read $ linkValue diff1info :: Payload
            let pNum = pN diff1dec
            let gNum = gN diff1dec
            let gAP = gAmodP diff1dec
            let (bNum, g2'', h2'') = genNum g2' h2'
            let gBP = (gNum ^ bNum) `mod` pNum
            let sessionKey = (gAP ^ bNum) `mod` pNum
            let sk = genSessionKey sessionKey
            let diff2 = AuthTunnel8 gBP
            let (diff2pack, g2''', h2''') = makeLinkPacket g2'' h2'' 0 diff2 recPrivKey sendPubKey
            send conn $ show diff2pack

            putStrLn ("Connected!")
            hFlush stdout
--            runnConn g2''' h2''' conn recPrivKey sendPubKey sk

            forkIO $ readSock g2''' h2''' conn recPrivKey sendPubKey sk
            writeSock g2''' h2''' conn recPrivKey sendPubKey sk

            sClose conn
            sClose sock
            
         where
           talk :: Socket -> IO ()
           talk conn = do msg <- LSock.recv conn 4096
                          unless (LB.null msg) $ LSock.sendAll conn msg >> talk conn


runnSock :: RandomGen a => CryptoRandomGen b => a -> b -> Socket -> PrivateKey -> PublicKey -> LB.ByteString -> IO ()
runnSock g h sock privK pubK sk = do putStr("> ")
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
                                     if newmsg == "quit" || newmsg == "exit"
                                     then sClose sock
                                     else return ()
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