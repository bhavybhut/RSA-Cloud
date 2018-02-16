import java.math.BigInteger;
import java.net.*; 
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.io.*; 

import javax.crypto.Cipher;
 
class RSASenderEncrypt{ 
	
	private static final String PUBLIC_KEY_FILE = "Public_Key_Sender.key";
	
	 public static void main(String[ ] args){ 
		 try{
			 InetAddress receiverHost = InetAddress.getLocalHost();
			 int receiverPort = Integer.parseInt("8888");
			 
			 BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		     System.out.print("Enter Input String:");
		     
		     //TCP CLient
		     	int filesize=1022386;
		        int bytesRead;
		        int currentTot = 0;
		        Socket socket = new Socket(receiverHost,9898);
		        byte [] bytearray  = new byte [filesize];
		        InputStream is = socket.getInputStream();
		        FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE);
		        BufferedOutputStream bos = new BufferedOutputStream(fos);
		        bytesRead = is.read(bytearray,0,bytearray.length);
		        currentTot = bytesRead;
		 
		        do {
		           bytesRead = is.read(bytearray, currentTot, (bytearray.length-currentTot));
		           if(bytesRead >= 0) currentTot += bytesRead;
		        } while(bytesRead > -1);
		 
		        bos.write(bytearray, 0 , currentTot);
		        bos.flush();
		        bos.close();
		        socket.close();
		        
			 String message = br.readLine();
			 double randomwatermark = Math.random(); 
			 
			 DatagramSocket mySocket = new DatagramSocket( );
			 
			 byte[] watermarkbuffer = new byte[8];
			 ByteBuffer.wrap(watermarkbuffer).putDouble(randomwatermark);
			 byte[] encryptbuffer = encryptData(message);
			 //File file = new File("Private.key");
			 //byte[] privatekey = new byte[(int) file.length()];
			 //FileInputStream fileInputStream = new FileInputStream(file);
             //fileInputStream.read(privatekey);
             byte[] senderbuffer = new byte[watermarkbuffer.length + encryptbuffer.length + watermarkbuffer.length];
			 
			 System.out.println("\n----------------WATERMARKING START------------");
			 System.arraycopy(watermarkbuffer, 0, senderbuffer, 0, watermarkbuffer.length);
			 System.arraycopy(encryptbuffer, 0, senderbuffer, watermarkbuffer.length, encryptbuffer.length);
			 System.arraycopy(watermarkbuffer, 0, senderbuffer, watermarkbuffer.length+encryptbuffer.length, watermarkbuffer.length);
			 
			 System.out.println("\n----------------WATERMARKING COMPLETE------------");
			 
			 System.out.println("Data Successfully Sended.");
			 DatagramPacket packet = new DatagramPacket(senderbuffer, senderbuffer.length, receiverHost,receiverPort);
			 mySocket.send(packet);
			 mySocket.close();
			 //fileInputStream.close();
			 }
			 catch(Exception e)	{
				 e.printStackTrace( );
			 }
		 }
 
		 /**
		  * Encrypt Data
		  * @param data
		  * @throws IOException
		  */
		 private static byte[] encryptData(String data) throws IOException {
		         System.out.println("\n----------------ENCRYPTION STARTED------------");
		         
		         System.out.println("Data Before Encryption :" + data);
		         byte[] dataToEncrypt = data.getBytes();
		         byte[] encryptedData = null;
		         try {
		                 PublicKey pubKey = readPublicKeyFromFile(PUBLIC_KEY_FILE);
		                 Cipher cipher = Cipher.getInstance("RSA");
		                 cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		                 encryptedData = cipher.doFinal(dataToEncrypt);
		                 System.out.println("Encryted Data: " + encryptedData);
		                 
		         } catch (Exception e) {
		                 e.printStackTrace();
		         }        
		         
		         System.out.println("----------------ENCRYPTION COMPLETED------------");                
		         return encryptedData;
		 }
		 
		 
		 /**
	         * read Public Key From File
	         * @param fileName
	         * @return PublicKey
	         * @throws IOException
	         */
		 private static PublicKey readPublicKeyFromFile(String fileName) throws IOException{
	                FileInputStream fis = null;
	                ObjectInputStream ois = null;
	                try {
	                        fis = new FileInputStream(new File(fileName));
	                        ois = new ObjectInputStream(fis);
	                        
	                        BigInteger modulus = (BigInteger) ois.readObject();
	                    BigInteger exponent = (BigInteger) ois.readObject();
	                        
	                    //Get Public Key
	                    RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
	                    KeyFactory fact = KeyFactory.getInstance("RSA");
	                    PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
	                                        
	                    return publicKey;
	                    
	                } catch (Exception e) {
	                        e.printStackTrace();
	                }
	                finally{
	                        if(ois != null){
	                                ois.close();
	                                if(fis != null){
	                                        fis.close();
	                                }
	                        }
	                }
	                return null;
	        }
 
 } 