
amounts ={}
with open("/home/sgiek/vinter/instruction_addresses.txt", "r") as file:
    for row in file:
        if not int(row) in amounts:
            amounts[int(row)] =0;
        
        amounts[int(row)] += 1;


print(amounts.values())
