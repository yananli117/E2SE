//import java.io.Files;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

public class ComFile1{
    public static void main(String[] args){
	String size  = args[0];
	int sizeInt =  0;
	if(size!=null){
     		sizeInt = Integer.valueOf(size).intValue();
	}
	
        final String filePath = "./"+size+"mb";
        try (FileOutputStream outputStream = new FileOutputStream(filePath) ) {
            for (int i=0; i<sizeInt;i++){
		byte[] data = new byte[1<<20];
            	outputStream.write(data);
	     }
	      //  byte[] data1 = new byte[1<<25];
	      //  outputStream.write(data1);
	   // byte[] data3 = new byte[1<<23];
           // outputStream.write(data3); 
           // byte[] data2 = new byte[1<<22];
           // outputStream.write(data2);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } ;
    }
}
