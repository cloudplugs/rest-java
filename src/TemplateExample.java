import com.cloudplugs.rest.*;
import com.cloudplugs.util.Listener;

/**
 * Template based basic Java example.
 * Enroll the Thing using the Template Plug ID and get the Thing Credentials
 * Publish a random number to a predefined channel.
 */
public class TemplateExample
{
	// TODO: put here your Template PlugID
	private final static String ENROLL_TEMPLATEID = "mod-XXXXXXXXXXXXXXXXXXXXXXXX";
	// TODO: put here your Thing Hardware ID / Serial Number
	private final static String ENROLL_HWID = "XXXXXXXXXXXXXXXXXXXXXXXX";
	// TODO: put here your Thing Enroll Password
	private final static String ENROLL_PASS = "password";

	// will contain the generated Thing PlugID
	private static String AUTH_PLUGID = "dev-XXXXXXXXXXXXXXXXXXXXXXXX";
	// will contain the generated Thing Password for authentication
	private static String AUTH_PASS = "password";

	// the channel name used for publishing data
	private final static String CHANNEL = "temperature";

	private static RestClient restClient = new RestClient();
	private static RestManager restManager;

	// THE MAIN
	public static void main(String[] args) {
		log("==== CloudPlugs Template example");

		Opts opts = new Opts();
		restManager = restClient.getManager(opts);

		restManager.addListener(new Listener.Stub() {
			@Override
			public void onEvt(Object evt, Object value) {
				if(RestManager.EVT_ENROLL.equals(evt)) {
					Object[] auth   = (Object[])value;
					String authId   = (String)auth[0];
					String authPass = (String)auth[1];
					log("==== Enroll success, now using credentials: id="+authId+", pass="+authPass);
					opts.setAuth(authId, authPass, false);
					AUTH_PLUGID = authId;
					AUTH_PASS = authPass;
					makeDataRequests(restCallback);
				}
			}
		});

		int id = restManager.execEnrollProduct(ENROLL_TEMPLATEID, ENROLL_HWID, ENROLL_PASS, null, restCallback);
		log("<<<< [ request "+id+" ] trying to enroll Thing with template "+ENROLL_TEMPLATEID+" and hwid "+ENROLL_HWID);

		restManager.waitForIdle();

		log("==== Quitting");
		restClient.destroy();
		restClient.waitForStop();
		log(AUTH_PLUGID);
	}

	public static void makeDataRequests(RestCallback cb) {
		double data = getDataToPublish();
		int id = restManager.execPublishData(CHANNEL, data, null, cb);
		log("<<<< [ request "+id+" ] publishing data to channel '"+CHANNEL+"': "+data);
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
