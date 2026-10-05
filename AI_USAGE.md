Tool/model and date: Chatgpt, GPT-5.6 sol, 10/3/26
Purpose: Explain the homework in a condensed form to give me guidance to starting 
AI Conversation Log files: ai-log-1
What I used: I used the result as guidance for beginning the assignment
What I changed: N/A 
How I tested it: N/A
One error, limitation, or rejected suggestion: N/A

Tool/model and date: Chatgpt, GPT-5.6 sol, 10/3/26
Purpose: Learn how to go about coding task 1, as well as to see a final product to check with
AI Conversation Log files: ai-log-2
What I used: The function structure( a code skeleton), how to create and use cipher objects, how to make a relay function and use XOR to change the action.
What I changed: I changed the relay function so that it calculates an XOR_delta first before altering the plaintext, this allowed me to display the difference of values for the result. I also changed what the action was being changed to.
How I tested it: I tested different actions to change the result to and tested to see if each worked in the way that I wanted. I created print statements to display the original and modified messages. 
One error, limitation, or rejected suggestion: A limitation is that the code assumes that the attacker already knows the plaintext to be able to find where to edit the action.

Tool/model and date:Chatgpt, GPT-5.6 sol, 10/3/26
Purpose: Check my writing to see if I was missing anything
AI Conversation Log files: ai-log 3
What I used: Advice that told me to change wordage from relay attack to bit flipping attack
What I changed: I addressed the attack as a bit flipping attack instead of a relay attack
How I tested it: N/A
One error, limitation, or rejected suggestion: It suggested to change a whole phrase at the beginning first paragraph but I just went with editing the terminology to bit flipping attack.

Tool/model and date:Chatgpt, GPT-5.6 sol, 10/3/26
Purpose: Learn how to go about coding task 2, break down the handshake into smaller understandable pieces.
AI Conversation Log files: ai-log-3
What I used: function structure, how to load pem parameters from the ffdhe3072.pem file, syntax for private key signing.. I also used the explanation for how the transcript, shared secret, and derived keys fit togethher in the handshake.
What I changed: I changed suggested code to reduce unnecessary function calls and variables. I combined some steps directly in main() wwhere seperate variables were not needed. 
How I tested it: I created print statements that confirmed the Diffie-Hellman shared secrets were correct. I also printed out each value to make sure that the handshake completed properly
One error, limitation, or rejected suggestion:A limitation with the code is that it requires the ffdhe3072 file to exist int he same directory and will simply not run without it.

Tool/model and date:Chatgpt, GPT-5.6 sol, 10/3/26
Purpose: Learn how to go about coding task 3, break down the record secure code into smaller understandable pieces. 
AI Conversation Log files: ai-log-4
What I used: I used the imports that I was recommended, the function structure, directions on what open_record function was actually meant to do.
What I changed: I changed open_record and how it traversed the difference pieces it was meaning to validate. Originally it was using variables to traverse through, however since the header, version, direction, sequence, etc. was always in the same position I used hardcoded values. I also reorganized so that validationw as done together after every varaible was created.
How I tested it: I tested it using print statements in main to make sure I got an output that showed the code was working properly such as printing out the record and plain text after sealing and opening.
One error, limitation, or rejected suggestion: I rejected the AI when it suggested to use global variables to find the position of things like variables such as header, version, etc. It was inefficient and convoluted. 

Tool/model and date: GPT-5.6 sol, 10/4/26
Purpose: Figure out which tests cases could be covered by the test_records file
AI Conversation Log files: ai-log-5
What I used: The function structure/tests to include in the file
What I changed:I also added more test coverage into the records test file such as bidirectional messages to cover the minimum needed for task 4.
How I tested it: These were tested by running them in the python environment and seeing if the tests passed, and I ran it with flag -v to see individual tests
One error, limitation, or rejected suggestion: limitation was that it didnt cover the minimum tests that I had to implement for task 4(combined with what I had for test_handshake)

