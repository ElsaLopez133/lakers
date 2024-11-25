import pandas as pd
import matplotlib.pyplot as plt
import math
import numpy as np
import scipy.stats as st

# st.t.interval(0.95, len(a)-1, loc=np.mean(a), scale=st.sem(a))
       
def find_regions(df, column):
    regions = []
    state = 0
    start_time = None
    
    for time, value in zip(df['Time [s]'], df[column]):
        if state == 0 and value == 1:
            state = 1
            start_time = time
        elif state == 1 and value == 0:
            state = 0
            # regions.append([start_time, time])
            regions.append(np.array([start_time, time]))
    
    return regions

def elapsed_time(regions):
    dur = []
    for i in range(len(regions)):
        dur.append(float(regions[i][1]-regions[i][0]))
    return dur

def filter_handshakes(duration, time):
    # list of non-successful handshakes
    failures = []
    success = []
    for idx, item in enumerate(duration):
        if item > time:
            failures.append(idx)
        else:
            success.append(idx)
    return success, failures

# Data
method = 'STAT'
# df_gpi_test1 = pd.read_csv('/home/elopezpe/lakers/results/time/psk2-test1.csv')
# df_gpi_test2 = pd.read_csv('/home/elopezpe/lakers/results/time/psk2-test2.csv')
df_gpi = pd.read_csv('/home/elopezpe/lakers/results/time/stat-test5.csv')

regions = find_regions(df_gpi, 'Channel 3')
# regions.extend(find_regions(df_gpi_test2, "Channel 3"))
regions = [x * 1000 for x in regions]
# print(regions)

# We want to filter out all the regions that take more than 5000ms
print("number of handshakes: ", len(regions))
duration = elapsed_time(regions)
success, failures = filter_handshakes(duration, 5000)
print("successful handshakes: {}   failed handshakes: {}".format(len(success), len(failures)))

# Mapping
duration_success = [duration[i] for i in success]
# print(duration_success)

# Confidence Interval (95%)
interval = st.t.interval(
    0.95,                            # Confidence level
    df=len(duration_success)-1,      # Degrees of freedom
    loc=np.mean(duration_success),   # Mean
    scale=st.sem(duration_success)   # Standard error of the mean
)
interval = (float(interval[0]), float(interval[1]))
print("confidence interval 95%: ", interval)

# Average time
average = np.round(np.mean(duration_success), 2)
print("average time in ms: ", average)


methods = [method]
averages = [average]  # Replace with your computed average
conf_intervals = [interval]  # Replace with your computed interval

# Calculate error bars (difference between mean and confidence bounds)
errors = [((mean - low), (high - mean)) for mean, (low, high) in zip(averages, conf_intervals)]
lower_errors, upper_errors = zip(*errors)  # Split into separate lists

# Bar plot with error bars
# Setting up the figure
plt.figure(figsize=(6, 6))

plt.bar(
    methods, averages, 
    yerr=[lower_errors, upper_errors],  # Error bars
    capsize=5, color='skyblue', edgecolor='black'
)

# Labels and title
plt.ylabel('Duration (ms)')
plt.title('Average Handshake Duration with 95% Confidence Intervals')
plt.ylim(0, max(averages) + 500)  # Adjust y-axis for better visualization
plt.tight_layout()
plt.savefig('time-handshake.png')
plt.show()
