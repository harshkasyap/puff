import subprocess
import time
import statistics

REPEATS = 10
runtimes = []

#PYTHON_PATH = "/Users/sumanta/miniconda3/envs/py310/bin/python"


PYTHON_PATH = "/home/harsh_1921cs01/anaconda3/envs/charm39/bin/python"
#PYTHON_PATH="/home/ss25611/py39/bin/python3"

for i in range(REPEATS):
    print(f"Run {i+1}/{REPEATS}")

    start = time.time()

    puf = subprocess.Popen([PYTHON_PATH, 'challenge_puf.py'])
    server = subprocess.Popen([PYTHON_PATH, 'challenge_server.py'])
    runtime = time.time() - start

    time.sleep(6)

    start_c = time.time()
    client = subprocess.run([PYTHON_PATH, 'challenge_client.py'])

    #server.wait()
    #puf.wait()
    server.terminate()
    puf.terminate()

    runtime_c = time.time() - start_c
    runtimes.append(runtime+runtime_c)
    print(f"Run {i+1} finished in {runtime+runtime_c:.3f} seconds\n")

avg = sum(runtimes) / len(runtimes)
#std = statistics.stdev(runtimes)

print(f"Average Runtime over {REPEATS} runs: {avg:.3f} seconds")
#print(f"Std Dev: {std:.3f} seconds")

#print(f"{runtime:.3f}")
