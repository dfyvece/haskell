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

------------------------------------------------------------------------
--  Some sample keys
------------------------------------------------------------------------

-- Alice's public and private keys

kAlice :: PublicKey
kAlice =  PublicKey {public_size = 128, 
                     public_n = 117401071746927262568551549970999915730678832253072252828591317371606073397393799128036588976632605476114801601971992741835746964178331235138018597416210270916116690594776280550308215262222182812225789150503578062794498037898286347870367682572297392404144054024207558021012697506033244851470030993417089007159, 
                     public_e = 65537}

kAlicePriv :: PrivateKey
kAlicePriv =  PrivateKey {private_size = 128, 
                          private_n = 117401071746927262568551549970999915730678832253072252828591317371606073397393799128036588976632605476114801601971992741835746964178331235138018597416210270916116690594776280550308215262222182812225789150503578062794498037898286347870367682572297392404144054024207558021012697506033244851470030993417089007159, 
                          private_d = 117340165137845438149866978618954292691253117308894086958988312888785153817682927571963634095798793910339927816866372286929016180090227366148063417406259364260345512518274605480349988282968628690562304882046095536033166554960001489887905252867924094888373700742285955424160014305890755146758095771544843855049, 
                          private_p = 11208588427701182600088270252093480577193511418965991616238377444759191889587150945295793370771155555378466969608393497994456629845818570244465115602453853, 
                          private_q = 10474206676799671832312095255474423558834698649147999817905130827662896225964835514068729293147870280090827573740955649676141244041140084414368557132375203, 
                          private_dP = 4220943320500864955218861251227048852482351371287679831068910010172221124479467862885090565491739309195424947891040962059648589721757210638775028656614753, 
                          private_dQ = 9488748716118731653206607067958130538651065710950545450491257188598407187264571910611937178440914390333285378955006757662422475852824022334947824976826039, 
                          private_qinv = 4987058921677913888048297399595583296293021157269488900539250349227728002971631495877569240734231462038457416552611442347338252935650248110432032242163574}

-- Bob's public and private keys
kBob = PublicKey {public_size = 128, 
                  public_n = 163449367722338293370172803173615974434781268085759465269697120275402965191524335945264593616691806729925911550670980094839461650901912047059236202066757091987823929041184084966732730806776630492805410424240895825720952578929110714450807783892793314755665614684808560631413845134804005801483049655615673437993, 
                  public_e = 65537}
kBobPriv = PrivateKey {private_size = 128, 
                       private_n = 163449367722338293370172803173615974434781268085759465269697120275402965191524335945264593616691806729925911550670980094839461650901912047059236202066757091987823929041184084966732730806776630492805410424240895825720952578929110714450807783892793314755665614684808560631413845134804005801483049655615673437993,
                       private_d = 2671075466234711875726003207332387942988704672472777016095421148587158028596404531751199776667789569369221222679839169958543470529867827370804918937600085724614550949409006845973388739581108646153612653839659613792827803717163295448711757821797327894397900977659479065376932946369624965543927178128581551537, 
                       private_p = 0, private_q = 0, private_dP = 0, 
                       private_dQ = 0, private_qinv = 0}

-- AES key and initialization vector
aesKey :: B.ByteString 
aesKey = B.pack [239,77,71,33,48,147,29,174,252,69,228,231,38,64,157,44]

initVec :: B.ByteString
initVec = B.pack [67,43,12,98,241,235,211,167, 94,61,13,91,23,25,234,107]

------------------------------------------------------------------------
--  Querying for input/output files
------------------------------------------------------------------------

whichFiles :: String -> String -> IO (String, String)
whichFiles one two = 
    do putStr $ "Which file do you wish to " ++ one ++ "? "
       inFile <- getLine 
       putStr $ "Where do you want to place " ++ two ++ "? "
       outFile <- getLine
       return (inFile, outFile)

------------------------------------------------------------------------
--  Create a secure message
------------------------------------------------------------------------

create :: IO ()
create = do rng <- newGenIO :: IO SystemRandom
            (infile,outfile) <- whichFiles "encrypt" "encrypted file"
            plaintext <- LB.readFile infile
            let (msg,g) = createMsg rng "Alice" "Bob" kAlicePriv kBob 
                                    aesKey initVec plaintext
            writeFile outfile $ show msg


------------------------------------------------------------------------
--  Decode and integrity check a secure message
------------------------------------------------------------------------

decode :: IO ()
decode = do (infile,outfile) <- whichFiles "decode" "decoded result"
            stuff <- readFile infile
            let msg = read stuff :: Message
            let (val,bool) = decodeMsg kBobPriv kAlice msg
            putStrLn ("Boolean: " ++ show bool)
            if bool then (LB.writeFile outfile val) else return ()


prober :: IO ()
prober = do timer <- getClockTime
            let (CalendarTime _ _ _ _ _ _ pico _ _ _ _ _) = toUTCTime timer
            let epochSeconds = fromIntegral pico
            g <- return (mkStdGen epochSeconds)
            h <- newGenIO :: IO SystemRandom
            let (probe1,sendPrivKey,port,g',h') = sendProbe g h
            let sendPubKey = senderKey probe1
            putStrLn ("PROBE PHASE:")
            putStrLn (show probe1)
            let (probe2,recPrivKey,g'',h'') = respondProbe g' h' port
            let recPubKey = senderKey probe2
            putStrLn (show probe2)
            putStrLn ("")
            getChar
            putStrLn ("IDENTIFICATION PHASE:")
            let username = "Alice"
            let password = "password"
            let hashedPassword = hashPassword password
            putStrLn ("----------Packet 1----------")
            let (serverCT, g''',h''') = genCT g'' h''
            let id1 = AuthTunnel1 username serverCT
            let (id1pack,g'''',h'''') = makeLinkPacket g''' h''' 0 id1 sendPrivKey recPubKey
            putStrLn (show id1pack)
            putStrLn (show $ readLinkPacket id1pack recPrivKey sendPubKey)
            getChar
            putStrLn ("\n----------Packet 2----------")
            let (clientCT, g''''', h''''') = genCT g'''' h'''' 
            let id2 = AuthTunnel2 clientCT (genCR serverCT recPubKey hashedPassword 0)
            let (id2pack, g2, h2) = makeLinkPacket g''''' h''''' 0 id2 recPrivKey sendPubKey
            putStrLn (show id2pack)
            putStrLn (show $ readLinkPacket id2pack sendPrivKey recPubKey)
            getChar
            putStrLn ("\n----------Packet 3----------")
            let id3 = AuthTunnel3 (genCR clientCT sendPubKey hashedPassword 0)
            let (id3pack, g2', h2') = makeLinkPacket g2 h2 0 id3 sendPrivKey recPubKey
            putStrLn (show id3pack)
            putStrLn (show $ readLinkPacket id3pack recPrivKey sendPubKey)
            getChar
            putStrLn ("\n----------Packet 4----------")
            let id4 = AuthTunnel3 (genCR serverCT recPubKey hashedPassword 1)
            let (id4pack, g2'', h2'') = makeLinkPacket g2' h2' 0 id4 recPrivKey sendPubKey
            putStrLn (show id4pack)
            putStrLn (show $ readLinkPacket id4pack sendPrivKey recPubKey)
            getChar
            putStrLn ("\n----------Packet 5----------")
            let id5 = AuthTunnel3 (genCR clientCT sendPubKey hashedPassword 1)
            let (id5pack, g2'', h2'') = makeLinkPacket g2' h2' 0 id5 sendPrivKey recPubKey
            putStrLn (show id5pack)
            putStrLn (show $ readLinkPacket id3pack recPrivKey sendPubKey)
            putStrLn ("")
            putStrLn ("VERIFICATION PHASE:")
            let (seed1, g2''', h2''') = genSeed g2'' h2''
            putStrLn ("----------Packet 1----------")
            let ver1 = AuthTunnel4 seed1
            let (ver1pack, g2'''', h2'''') = makeLinkPacket g2''' h2''' 0 ver1 recPrivKey sendPubKey
            putStrLn (show ver1pack)
            putStrLn (show $ readLinkPacket ver1pack sendPrivKey recPubKey)
            getChar
            putStrLn ("----------Packet 2----------")
            let (seed2, g2''''', h2''''') = genSeed g2'''' h2''''
            let cliKeyCheck = kvf seed1 seed2 recPubKey hashedPassword
            let ver2 = AuthTunnel5 seed2 cliKeyCheck
            let (ver2pack, g3, h3) = makeLinkPacket g2''''' h2''''' 0 ver2 sendPrivKey recPubKey
            putStrLn (show ver2pack)
            putStrLn (show $ readLinkPacket ver2pack recPrivKey sendPubKey)
            getChar
            putStrLn ("\n----------Packet 3----------")
            let recKeyCheck = kvf seed2 seed1 sendPubKey hashedPassword
            let ver3 = AuthTunnel6 recKeyCheck
            let (ver3pack, g3', h3') = makeLinkPacket g3 h3 0 ver3 recPrivKey sendPubKey
            putStrLn (show ver3pack)
            putStrLn (show $ readLinkPacket ver3pack sendPrivKey recPubKey)
            putStrLn ("SESSION KEY GENERATION")
            putStrLn ("\n----------Packet 1----------")
            let (p, g3'', h3'') = genPrime g3' h3'
            let (g, g3''', h3''') = genNum g3'' h3''
            let (a, g3'''', h3'''') = genNum g3''' h3'''
            let gAmodP = (g ^ a) `mod` p
            let diff1 = AuthTunnel7 p g gAmodP
            let (diff1pack, g3''''', h3''''') = makeLinkPacket g3'''' h3'''' 0 diff1 sendPrivKey recPubKey
            putStrLn (show diff1pack)
            putStrLn (show $ readLinkPacket diff1pack recPrivKey sendPubKey)
            getChar
            putStrLn ("\n----------Packet 2----------")
            let (b, g3''''', h3''''') = genNum g3'''' h3''''
            let gBmodP = (g ^ b) `mod` p
            let sessionKey = (gAmodP ^ b) `mod` p
            let diff2 = AuthTunnel8 gBmodP
            let (diff2pack, g4, h4) = makeLinkPacket g3''''' h3''''' 0 diff2 recPrivKey sendPubKey
            putStrLn (show diff2pack)
            putStrLn (show $ readLinkPacket diff2pack sendPrivKey recPubKey)
            putStrLn ("\nCOMMUNICATION READY")
            putStrLn ("Session Key: " ++ (show $ genSessionKey sessionKey))
            let message = "Hello, World!"
            getChar
            let sk = genSessionKey sessionKey
            let msg1 = genMsg sk message
            let (msg1pack, g4', h4') = makeLinkPacket g4 h4 0 msg1 sendPrivKey recPubKey
            putStrLn (show msg1pack)
            putStrLn (show $ readLinkPacket msg1pack recPrivKey sendPubKey)
            getChar
            let (Just val) = readLinkPacket msg1pack recPrivKey sendPubKey
            let uncr = linkValue val
            let inf = read uncr :: Payload
            putStrLn (show $ readMsg sk inf)
            putStrLn ("")
            
            

server :: IO ()
server = withSocketsDo $          
         do timer <- getClockTime
            let (CalendarTime _ _ _ _ _ _ pico _ _ _ _ _) = toUTCTime timer
            let epochSeconds = fromIntegral pico
            g <- return (mkStdGen epochSeconds)
            h <- newGenIO :: IO SystemRandom

            putStr ("Enter server IP address: ")
            addr <- getLine
            putStr ("Enter server port: ")
            portnum <- getLine
            putStr ("Enter password: ")
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
            runnConn g2''' h2''' conn recPrivKey sendPubKey sk

            forkIO $ readSock g2''' h2''' conn recPrivKey sendPubKey sk
            writeSock g2''' h2''' conn recPrivKey sendPubKey sk

            sClose conn
            sClose sock
            
         where
           talk :: Socket -> IO ()
           talk conn = do msg <- LSock.recv conn 4096
                          unless (LB.null msg) $ LSock.sendAll conn msg >> talk conn

                          
                          
client :: IO ()                          
client = withSocketsDo $
         do putStr ("Enter IP address to connect to: ")
            addr <- getLine
            putStr ("Enter server port number: ")
            portnum <- getLine
            putStr ("Enter password: ")
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

            forkIO $ readSock g2''''' h2''''' sock sendPrivKey recPubKey sk
            writeSock g2''''' h2''''' sock sendPrivKey recPubKey sk
--            runnSock g2''''' h2''''' sock sendPrivKey recPubKey sk
            sClose sock


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
readSock g h sock privK pubK sk = do putStr("> ")
                                     newmsg <- getLine
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
                                      putStrLn ("< " ++ (show $ readMsg sk inf))
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