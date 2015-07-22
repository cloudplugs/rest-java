import com.cloudplugs.rest.*;

/**
 * Basic Java example.
 * Publish a random number to a predefined channel.
 */
public class BasicExample
{
	// TODO: put here your prototype PlugID
	private final static String AUTH_PLUGID = "dev-XXXXXXXXXXXXXXXXXXXXXXXX";
	// TODO: put here your password
	private final static String AUTH_PASS = "password";
	// leave true for using your account password (or set it to false for using the specific prototype password)
	private final static boolean AUTH_MASTER = true;

	// the channel name used for publishing data
	private final static String CHANNEL = "temperature";

	// THE MAIN
	public static void main(String[] args) {
		log("==== CloudPlugs basic example");
		RestClient restClient = new RestClient();
		RestManager restManager = restClient.getManager(new Opts().setAuth(AUTH_PLUGID, AUTH_PASS, AUTH_MASTER));

		double data = getDataToPublish();
		int id = restManager.execPublishData(CHANNEL, data, null, restCallback);
		log("<<<< [ request "+id+" ] publishing data to channel '"+CHANNEL+"': "+data);

		restManager.waitForIdle();

		log("==== Quitting");
		restClient.destroy();
		restClient.waitForStop();
	}

	private static double getDataToPublish() {
		return Math.random() * 100;
	}

	private static void log(final String msg) {
		System.out.println(msg);
	}

	private static RestCallback restCallback = new RestCallback() {
		/**
		 * Implementation of com.cloudplugs.rest.RestCallback .
		 * It will be automatically called after each executed request.
		 * @param request the generated request
		 * @param response the received response from the server
		 */
		@Override
		public void on(Request request, Response response) {
			// just log the result
			String state = null;
			if(!response.isCompleted())   state = "interrupted";
			else if(response.isSuccess()) state = "successful";
			else if(response.isPartial()) state = "partially completed";
			else if(response.isFailed())  state = "failed";
			log(">>>> [ request " + request.getId() + " ] " + state + ", response is: " + response);
		}
	};
}
