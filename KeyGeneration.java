import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


public class KeyGeneration {
	
	private static final String PUBLIC_KEY_FILE = "Public.key";
    private static final String PRIVATE_KEY_FILE = "Private.key";
    
    public static void main(String[] args) throws IOException {

            try {
                    System.out.println("-------GENRATE PUBLIC and PRIVATE KEY-------------");
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                    keyPairGenerator.initialize(2048); //1024 used for normal securities
                    KeyPair keyPair = keyPairGenerator.generateKeyPair();
                    PublicKey publicKey = keyPair.getPublic();
                    PrivateKey privateKey = keyPair.getPrivate();
                    System.out.println("Public Key - " + publicKey);
                    System.out.println("Private Key - " + privateKey);

                    //Pullingout parameters which makes up Key
                    System.out.println("\n------- PULLING OUT PARAMETERS WHICH MAKES KEYPAIR----------\n");
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
                    RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
                    System.out.println("PubKey Modulus : " + rsaPubKeySpec.getModulus());
                    System.out.println("PubKey Exponent : " + rsaPubKeySpec.getPublicExponent());
                    System.out.println("PrivKey Modulus : " + rsaPrivKeySpec.getModulus());
                    System.out.println("PrivKey Exponent : " + rsaPrivKeySpec.getPrivateExponent());
                    
                    //Share public key with other so they can encrypt data and decrypt thoses using private key(Don't share with Other)
                    System.out.println("\n--------SAVING PUBLIC KEY AND PRIVATE KEY TO FILES-------\n");
                    RSA_ALGO rsaObj = new RSA_ALGO();
                    saveKeys(PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
                    saveKeys(PRIVATE_KEY_FILE, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());
                    
                    //Send Files to client
       			 	ServerSocket serverSocket = new ServerSocket(9898);
       			 	ServerSocket serverSocket2 = new ServerSocket(8989);
       			 	while(true){
       			 		Socket socket = serverSocket.accept();
       			 		Socket socket2 = serverSocket2.accept();
		       			if(socket.isConnected())
		       			{
		       				System.out.println("Accepted connection : " + socket);
			                File transferFile = new File (PUBLIC_KEY_FILE);
			                byte [] bytearray  = new byte [(int)transferFile.length()];
			                FileInputStream fin = new FileInputStream(transferFile);
			                BufferedInputStream bin = new BufferedInputStream(fin);
			                bin.read(bytearray,0,bytearray.length);
			                OutputStream os = socket.getOutputStream();
			                System.out.println("Sending Files...");
			                os.write(bytearray,0,bytearray.length);
			                os.flush();
			                socket.close();
			                System.out.println("File transfer complete");
		       			}
		       			if(socket2.isConnected())
		       			{
		       				System.out.println("Accepted connection : " + socket2);
			                File transferFile = new File (PRIVATE_KEY_FILE);
			                byte [] bytearray  = new byte [(int)transferFile.length()];
			                FileInputStream fin = new FileInputStream(transferFile);
			                BufferedInputStream bin = new BufferedInputStream(fin);
			                bin.read(bytearray,0,bytearray.length);
			                OutputStream os = socket2.getOutputStream();
			                System.out.println("Sending Files...");
			                os.write(bytearray,0,bytearray.length);
			                os.flush();
			                socket2.close();
			                System.out.println("File transfer complete");
		       			}
       			 	}

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
        }catch (InvalidKeySpecException e) {
                e.printStackTrace();
        }
    }           
            /**
             * Save Files
             * @param fileName
             * @param mod
             * @param exp
             * @throws IOException
             */
            private static void saveKeys(String fileName,BigInteger mod,BigInteger exp) throws IOException{
                    FileOutputStream fos = null;
                    ObjectOutputStream oos = null;
                    
                    try {
                            System.out.println("Generating "+fileName + "...");
                            fos = new FileOutputStream(fileName);
                            oos = new ObjectOutputStream(new BufferedOutputStream(fos));
                            
                            oos.writeObject(mod);
                            oos.writeObject(exp);                        
                            
                            System.out.println(fileName + " generated successfully");
                    } catch (Exception e) {
                            e.printStackTrace();
                    }
                    finally{
                            if(oos != null){
                                    oos.close();
                                    
                                    if(fos != null){
                                            fos.close();
                                    }
                            }
                    }                
            }
}
