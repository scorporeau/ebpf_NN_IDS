import pandas
import numpy as np
import matplotlib.pyplot as plt

df = pandas.read_csv('net_listener_tc.csv', sep=',')

time_parsing = df['time_parsing']

iperf = df[df['portD'] == 5201]['time_parsing']
other = df[df['portD'] != 5201]['time_parsing']
p1, p10, median, p90, p99 = time_parsing.quantile(0.01), time_parsing.quantile(0.10), time_parsing.median(), time_parsing.quantile(0.90), time_parsing.quantile(0.99)

plt.hist(
    [other, iperf],
    bins=500,
    range=(0, 500),
    log=True,
    color=['tab:blue', 'tab:orange'],
    label=['other', 'iperf'],
    stacked=True,
)



plt.xlabel('parsing time (ns)')
plt.ylabel('# of packets (log scale)')
plt.title('Histogram of time_parsing for TC')
plt.legend()
plt.xlim(0, 500)
plt.xticks(range(0,501,20))
plt.subplots_adjust(left=0.05, right=0.95, bottom=0.05, top=0.95)

ymax = plt.ylim()[1]
percentiles = {
    '1%': p1,
#    '10%': p10,
    '50%': median,
    '90%': p90,
    '99%': p99,
}
for label, x in percentiles.items():
    plt.axvline(x, color='black', linestyle='--', linewidth=1)
    plt.text(x, ymax * 0.75, label, rotation=90, va='top', ha='right', fontsize=8, color='black')

plt.show()