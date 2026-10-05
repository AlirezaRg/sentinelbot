# Ownership checklist

Use this list to check your own understanding before the defense. Tick a box only if you can do the thing without looking at the documents, on a whiteboard or in a terminal. If a box is not ticked, read the linked section again and try again.

## Architecture

- [ ] I can draw the pipeline from Linux host to dashboard, with the data format at each arrow. (`docs/architecture-explained.md`)
- [ ] I can explain why detection runs on the server and not on the agent, including the trade-off. (`docs/must-understand.md`, architecture section)
- [ ] I can name the five things the agent does and the four things the server does with the events.
- [ ] I can explain why the event model is shared between the agent and the server.

## Agent and logs

- [ ] I can say what a sshd `Failed password` line becomes after parsing, and which fields are kept.
- [ ] I can explain why "Invalid user" lines are ignored.
- [ ] I can explain how the agent avoids reading a line twice, and what happens after log rotation.
- [ ] I can explain why the Docker agent needs the journal group and host PID, and what that means for security.

## Detection

- [ ] I can state the threshold and window of each of the five rules from memory.
- [ ] I can walk through the SSH brute-force rule step by step: failed login, source IP, window, count, threshold, detection, cooldown.
- [ ] I can explain why eight failures produce one detection.
- [ ] I can explain the difference between a rule window (300 s) and the correlation gap (1800 s).
- [ ] I can list one false positive and one false negative for each rule. (`docs/detection-rules.md`)

## Risk scoring

- [ ] I can write the formula and name each factor with its default value.
- [ ] I can compute the score of the `campaign` root detection by hand: 60.
- [ ] I can explain why the rule's severity is a floor.
- [ ] I can explain why the incident takes the maximum score and not the sum.
- [ ] I can say, without hesitation, that the score is heuristic and not validated.

## Correlation and incidents

- [ ] I can define event, detection and incident, and give an example of each.
- [ ] I can explain the grouping key and the gap, and why the gap is 30 minutes.
- [ ] I can describe the incident lifecycle and explain why RESOLVED is never reused.
- [ ] I know which status changes the API supports and which only the CLI supports. (`docs/correlation-explained.md`)

## AI analyst

- [ ] I can say why the AI exists in the system, and why it does not detect.
- [ ] I can list the fields the model receives and the fields it does not.
- [ ] I can explain the three validation steps and the confidence cap.
- [ ] I can describe the fallback behavior and the four cases in its table.
- [ ] I can explain one prompt-injection risk and its mitigation.

## Storage, API and deployment

- [ ] I can explain why PostgreSQL and why Redis, and what Redis does that the process memory cannot.
- [ ] I can describe what happens if PostgreSQL is unavailable, and say which part of that answer is not tested.
- [ ] I can explain why migrations are tested against the models.
- [ ] I can describe how a request reaches the API from the browser (the rewrite).
- [ ] I can explain the difference between the Compose and Kubernetes deployments.

## Testing and evaluation

- [ ] I can run the agent and detection test suites, and I know the one skipped test needs Redis.
- [ ] I can run the laboratory scenarios and explain each expected result.
- [ ] I can say which metrics are measured, which are functional checks, and which are not yet measured.
- [ ] I can describe how I would measure detection rate and false-positive rate. (`docs/evaluation.md`)

## Honesty

- [ ] I can say which parts of the code I designed, which parts I wrote with tool assistance, and which parts are framework code.
- [ ] I can name at least three limitations without being asked.
- [ ] I can say what is not implemented (for example, the Docker security check) without presenting it as working.
- [ ] I will not present a number as a result unless it appears in a measured document.

## Final test

- [ ] I can explain one complete attack from the first failed login to the analyst's recommended actions, in five minutes, without notes.
