# Design Idea

We are going to design the Signature Validation System (SVS) for ACE.

The SVS will be a new subsystem of ACE that is designed to 

- validate that newly created or modified signatures match the telemetry they are designed to match (or matched previously.)
- validate the telemetry that signatures are designed to match is actually generated in the environment ACE is operating in.
- validate that a given MITRE ATT&CK technique is actually covered by one or more detection signatures.

We intend to accomplish this by

- recording matched telemetry that has been labeled with a disposition (only possible with yara rules).
- applying newly created or modified signatures to the recorded telemetry to ensure they match or still match (only possible for yara rules).
- performing operations in a controlled environment that generates detectable telemetry.
- validating the the signatures that should have fired for the generated detectable telemetry actually fired.

Consider the following:

`d(X) = { T, F }` where `d` is a detection signature as a function, X is some kind of telemetry, and the result is either "it matched" or "it did not match". This is the essense of a detection signature. For the purposes of this discussion, we'll call this "static detection", because X is simply static data. 

Then we take it a step further by turning X into a function: `d(t(Y)) = { T, F }` where `t(Y)` is function (an operation) that generates the telemetry (based on some input `Y`). We'll call this "dynamic detection" because `t(Y)` may return a different value based on `Y`.

An example static detection is applying a yara rule to a PDF file. The PDF file does not change.

An example dynamic detection is applying a yara rule to the output of a PDF parsing tool that is fed a PDF file. The output may change based on the version of the tool.

The SVS system will be designed to support both of these ideas.

# Key Changes to ACE

## True Positive vs False Positive

ACE will have a configuration setting that defines if a given alert disposition classifies as True Positive or False Positive.

## Dispositions for Detection Points

ACE will have the ability to assign a disposition to a detection point. Today that is only supported for alerts. An alert has one or more detection points. 

- If an ACE alert has a single detection point, then the detection point automatically inherit the disposition on the alert, no additional steps required.
- If an ACE alert is dispositioned as False Positive, then all detection points are also dispositioned as False Positive.
- If an ACE alert is dispositioned as True Positive and has more than one detection point, the an additional step will be *optional* that will allow the analyst to decide if any detection points in the alert were actually False Positive.
  - We need to decide how this is going to work in the GUI.
- If the analysts ops to NOT disposition all detection points, then the disposition for the detection points are left empty (NULL) and are subquently ignored for logic that uses the disposition of detection points.
- If the disposition changes, the same logic is applied again.
- The analyst is free to come back later and assign dispositions to detection points.

# Regression Detection

## Yara Signature Development

- ACE will use the analysts disposition of an ACE detection points to "label" file samples that matched yara rules.
- ACE records *all* data that would be required to re-scan the file, including the file data.
  - If the data we want to record is missing for any reason, an ERROR log is generated and no changes are made to the sample data tracking.
- If the disposition was a True Positive, then the sample becomes a True Positive sample.
- If the disposition was a False Positive, then the sample becomes a False Positive sample.
- When a PR is submitted to a yara signature repository, ACE determines which yara signatures have been modified. Then it looks to see if those yara signatures had any recorded detection data. If so, ACE runs the modified verions of the yara signatures against the data, and reports any differences.
- This report must then be reviewed by an analyst. The analyst is then able to modify the baseline using their review of the report.
  - We still need to determine how exactly this works.
- True Negative samples are out of scope.

### Sample Storage

- YARA regression samples are stored through ACE's existing storage subsystem (`saq/storage`), content addressed by sha256.
- Sample identity and labels live in the ACE database.

## Other Detection Signatures

Detections based on other types of signatures are not in scope for regression detection.

# Atomic Red Team Testing

## Test Execution & Security

The preparation of target hosts and the launching of the execution of atomic red team tests are not in scope for ACE. This should be a separate project that is custom to each site installation.

- Which hosts are considered "test" hosts for SVS are defined by configuration.
- When a test is created, a call is made to ACE to register the following information
  - which test is being executed
  - which assets or targets are in scope for the test (hostname, username)
  - any additional information needed to enable ACE to identify alerts triggered by the test
- An attempt to register a test that has not been predefined as a "test host" generates an ACE alert.
- The registration returns a special token that can be used by the launcher to help ACE identify events associated to testing activity.
  - ACE records the token and associates the token to the test that was registered.
  - The token is random.
- A special set of permissions allow tests to be registered.
- ACE will have an easy button to allow an analyst to disassociate an alert to a test.
- ACE will have an easy button to allow an analyst to associate any alert to any test.

## Test Lifecycle

Even if all expected sigantures fire, there is still a chance that additional new signature may fire later that we're not expecting. So, each test has a time frame during which ACE is expecting alerts to be associated to the test. Once this time has elapsed, the test is considered "ended".

- Created: the test has been registered and is awaiting execution
- Started: the test has started and is waiting
- Ended: the amount of time the test has to execute has passed
- Canceled: the test has been manually canceled, results are invalid
- Error: something went wrong when executing the test, results are invalid

## ACE Support of Atomic Red Team Tests

- ACE allows multiple git repositories of Atomic Red Team tests (allowing for custom tests.)
- ACE is able to automatically determine when an alert is generated from the execution of an atomic red team test and is able to identify the test.
- ACE intelligently moves alerts identified as belonging to the execution of tests to special dedicated queue as soon as ACE is able to make that determination.
- ACE allows an analyst to assign a mapping of a single atomic red team test to the list of signatures that are expected to fire.
- ACE tracks both expected and unexpected detection points for a given test
- ACE allows an analyst to ignore specific signatures for specific tests.
- ACE allows an analyst to review the results of the execution of a test and perform the following operations
  - review missing detections
  - map unexpected detections
  - ignore future detections
  - remap detection to a different test in the event the test assignment is incorrect

# Design Decisions 

These are the decisions we're making as we go back and forth on the design.

- We are allowed to make the changes to ACE that we need to make to support SVS.
- The possibility of a real-world True Positive on a test machine is intentionally left out of scope.
- The management and execution of atomic red team tests and targets is outside the scope of ACE.
- "Marker injection" will be used to help identify alerts created from test execution. Best effort in the edge cases where marker injection is not possible.
- SVS will consist of three major subsystems:
  - Static Regression (signature repo --> sample store)
  - Test Execution (targets --> runs --> attributed alerts)
  - Coverage (techniques x signatures x runs)
- Test-to-signature mapping is derived first from declared techniques, and then hand-edited mappings.
