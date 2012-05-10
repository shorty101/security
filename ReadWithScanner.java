import java.io.*;
import java.util.Scanner;

public class ReadWithScanner {
	private final File fFile;

	/**
   Constructor.
   @param aFileName full name of an existing, readable file.
	 */
	public ReadWithScanner(String aFileName){
		fFile = new File(aFileName);  
	}

	/** Template method that calls {@link #processLine(String)}.  */
	public final Tuple<String, String, String> processLineByLine() throws FileNotFoundException {
		//Note that FileReader is used, not File, since File is not Closeable
		Tuple<String, String, String> tuple = new Tuple<String, String, String> (null,null,null);
		
		Scanner scanner = new Scanner(new FileReader(fFile));
		try {
			//first use a Scanner to get each line
			while ( scanner.hasNextLine() ){
				tuple = processLine( scanner.nextLine() );
			}
		}
		finally {
			//ensure the underlying stream is always closed
			//this only has any effect if the item passed to the Scanner
			//constructor implements Closeable (which it does in this case).
			scanner.close();
		}
		return tuple;
	}

	/** 
   Overridable method for processing lines in different ways.

   <P>This simple default implementation expects simple name-value pairs, separated by an 
   '=' sign. Examples of valid input : 
   <tt>height = 167cm</tt>
   <tt>mass =  65kg</tt>
   <tt>disposition =  "grumpy"</tt>
   <tt>this is the name = this is the value</tt>
	 */
	protected Tuple<String,String,String> processLine(String aLine){
		//use a second Scanner to parse the content of each line 
		Scanner scanner = new Scanner(aLine);
		scanner.useDelimiter("=");
		if ( scanner.hasNext() ){
			String user = scanner.next();
			String pubK = scanner.next();
			String priK = scanner.next();
			log("User is: " + quote(user.trim()) + ", public key is : " + quote(pubK.trim()) + ", private key is: " + quote(priK.trim()) );
			Tuple<String, String, String> t = new Tuple<String,String,String> (user.trim(), pubK.trim(), priK.trim());
			return t;
		}
		else {
			log("Empty or invalid line. Unable to process.");
		}
		//no need to call scanner.close(), since the source is a String
		return new Tuple<String,String,String>(null,null,null);
	}

	private static void log(Object aObject){
		System.out.println(String.valueOf(aObject));
	}

	private String quote(String aText){
		String QUOTE = "'";
		return QUOTE + aText + QUOTE;
	}

	public static void main(String... aArgs) throws FileNotFoundException {
		ReadWithScanner parser = new ReadWithScanner("C:\\Temp\\test.txt");
		parser.processLineByLine();
		log("Done.");
	}

} 