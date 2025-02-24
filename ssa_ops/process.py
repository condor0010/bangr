with open("list.txt","r") as l:
    lines = l.readlines()
    for l in lines:
        e = l.split(',')
        print(f'elif inst.operation == {e[0]}:')
        print('    continue')
    
