# Overview

We are going to design the Signature Validation System (SVS) for ACE.

The SVS will be a new subsystem of ACE that is designed to 

- validate that newly created or modified signatures match the telemetry they are designed to match (or matched previously.)
- validate the telemetry that signatures are designed to match is actually generated in the environment ACE is operating in.
- validate that a given technique is actually covered by one or more detection signatures.

We intend to accomplish this by

- recording matched True Positive telemetry (when possible).
- applying newly created or modified signatures to the recorded telemetry to ensure they match (or still match.)
- performing operations in a controlled environment that generates detectable telemetry.
- validating the the signatures that should have fired for the generated detectable telemetry actually fired.

Consider the following:

`d(X) = { T, F }` where `d` is a detection signature as a function, X is some kind of telemetry, and the result is either "it matched" or "it did not match". This is the essense of a detection signature. For the purposes of this discussion, we'll call this "static detection", because X is simply static data. 

Then we take it a step further by turning X into a function: `d(t(Y)) = { T, F }` where `t(Y)` is function (an operation) that generates the telemetry (based on some input `Y`). We'll call this "dynamic detection" because `t(Y)` may return a different value based on `Y`.

An example static detection is applying a yara rule to a PDF file. The PDF file does not change.

An example dynamic detection is applying a yara rule to the output of a PDF parsing tool that is fed a PDF file. The output may change based on the version of the tool.

The SVS system will be designed to support both of these ideas.

# Requirements

This is how we'd like to see this work.

## Signature Development

- When a PR is submitted to a signature repository, ACE determines which signatures have been modified. Then it looks to see if those signatures had any recorded detection data. If so, ACE runs the modified verions of the signatures against the data, and reports if there are any regressions (something used to match but does not now.)
- When an analyst dispositions an alert as a True Positive, ACE records the detection data so that it can check future modifications to the signatures that generated the alert.
  - A future changes to a non-TP disposition removes these records.

## Atomic Red Team Testing

- ACE directly supports the Atomic Red Team system.
- ACE allows multiple git repositories of Atomic Red Team tests (allowing for custom tests.)
- ACE allows an ACE system administator to configure remote systems available for use for atomic red team testing.
- ACE allows an analyst to launch one or more Atomic Red Team tests.
- ACE is able to automatically determine when an alert is generated from the execution of an atomic red team test.
- ACE intelligently moves alerts identified as belonging to the execution of tests to special dedicated queue.
- ACE allows an analyst to assign a mapping of an atomic red team test to the list of signatures that are expected to fire.
- ACE tracks both expected and unexpected alerts for a given test
- ACE allows an analyst to ignore specific signatures for specific tests (for example, some remote set may fired detections)
- ACE allows an analyst to review the results of an execution of a test, and, perform the following operations
  - review missing detections
  - map unexpected detections
  - ignore future detections
  - possible remap to different tests (maybe?)

- ACE is designed to handle the built-in delay of detections. Some signatures, such as hunts, run on a longer frequency, so ACE does not expect results immediately.

