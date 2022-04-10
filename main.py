from hashlib import blake2b, blake2s, sha256
import hmac
import time

# For the sake of simplicity we will increase the last number by one and append it
private_seed = b"Hello world"

verifier_list = []
for i in range(0,10):

    print("=========SENDER=========")
    # Perform the HMAC operation
    message = b"crypt"
    attached_key = private_seed
    if i != 0:
        private_seed = private_seed[:-1]
    private_seed = private_seed+i.to_bytes(1, 'big')

    hm = hmac.new(msg=message, key=private_seed, digestmod=sha256)
    # print(len(hm.digest()))

    # Scheme I: Ti = T0 + i/r
    r = 1 # One packet every 1 second
    
    # Append the message, the HMAC and the previous key
    # Special condition: since for the first message there is no previous key
    if i == 0:
        T0 = time.time() 
        Ti = T0 + i/r
        # TODO: Move that to a tuple for now, it is easier to do the operations
        # TODO: Attach the Ti to the message
        sent_message = (message, hm.digest(), None, Ti)
    else:        
        Ti = T0 + i/r
        # TODO: Move that to a tuple for now, it is easier to do the operations
        # TODO: Attach the Ti to the message
        sent_message = (message, hm.digest(), attached_key, Ti)        


    # print(sent_message)
    # print("Previous key {0}".format(attached_key))
    # print("Current key {0}".format(private_seed))    

    # Now the verifier should store and verify the message based on the next disclosed key
    print("=========RECEIVER=========")
    
    Arr_Ti = time.time() # Just simulate the arrival time
    
    received_message = sent_message + (Arr_Ti,)
    print(received_message)
    # Special condition: If it is the first message there is no previous message to verify
    if i == 0:                
        verifier_list.append(received_message)        
    else:
        verifier_list.append(received_message)
        message_for_verification = verifier_list[i-1]
        print(message_for_verification)
        # prev_message = message_for_verification[:5]
        prev_message = message_for_verification[0]

        # print(prev_message)         
        prev_hm = message_for_verification[1]   
        # print(prev_hm)
        prev_key = received_message[2]
        # print(prev_key)

        current_Ti = received_message[3]
        # print(current_Ti)        

        # TODO: Here perform the check ArrTi + δt < Ti+1
        # What constitutes as δt? ReceiverTime - SenderTime?
        delta_t = 1

        print("ArrTi of previous: {0}".format(message_for_verification[4]))
        print("delta_t: {0}".format(delta_t))
        print("ArrTi + delta_t: {0}".format(message_for_verification[4]+delta_t))
        print("current_Ti: {0}".format(current_Ti))

        verify_1 = False
        if ((Arr_Ti + delta_t < current_Ti)):        
            verify_1 = True

        hm_val = hmac.new(msg=prev_message, key=prev_key, digestmod=sha256)
        # print("New digest {0}".format(hm_val.digest()))

        verify_2 = hmac.compare_digest(hm_val.digest(), prev_hm)
        
        if verify_1 and verify_2:
            print("Verification of message {0} has been achieved".format(i-2))
            

    #  Just wait for #num second(s) before "sending" the next packet
    # time.sleep(2)
        


    