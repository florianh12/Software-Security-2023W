import subprocess
import time

args = ['usr', 't26WIexMB6']
file_path_output = "output.txt"
sample_size = 100000

with open(file_path_output, "a") as file:
    for i in range(8):
        if i == 0:
            command = "./keycheck.bin"
        else:
            command = "./keycheck_"+str(i)+".bin"

        command = [command] + args
        command = ' '.join(command)
        average = 0.

        for _ in range(sample_size):
            start_time = time.time()

            subprocess.run(command, shell=True, stdout=file, stderr=subprocess.STDOUT)

            stop_time = time.time()

            average += (stop_time - start_time)

        average = average/float(sample_size)

        if i == 0:
            print("Execution time keycheck.bin:   "+str(average))
        else:
            print("Execution time keycheck_"+str(i)+".bin: "+str(average))