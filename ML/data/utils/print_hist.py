import pandas
import numpy as np
import matplotlib.pyplot as plt
import argparse
#retrieve arguments

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, default='../self/logs/2026-04-17/net_listener_tc.csv', help='input csv file')
parser.add_argument('--title', type=str, default='TC', help='partial title of the plot')
parser.add_argument('--limit', type=float, default=0.999, help="Percentile limit for x-axis (e.g., 0.999 for 99.9th percentile)")
parser.add_argument('--feature', type=str, default='time_parsing', help='feature to plot (must exactly match column name in csv)')
args = parser.parse_args()

df = pandas.read_csv(args.input, sep=',')

feature = df[args.feature]

iperf = df[df['portD'] == 5201][args.feature]
other = df[df['portD'] != 5201][args.feature]
p1, p10, median, p90, p99 = feature.quantile(0.01), feature.quantile(0.10), feature.median(), feature.quantile(0.90), feature.quantile(0.99)

if args.limit < 1:
    lim = int(feature.quantile(args.limit))
elif args.limit == 1:
    lim = int(feature.max())
else:
    lim = int(args.limit)


plt.hist(
    [other, iperf],
    bins=lim,
    range=(0, lim),
    log=True,
    color=['tab:blue', 'tab:orange'],
    label=['other', 'iperf'],
    stacked=True,
)



plt.xlabel(args.feature)
plt.ylabel('# of packets (log scale)')
plt.title('Histogram of ' + args.feature + ' for ' + args.title)
plt.legend()
plt.xlim(0, lim)
plt.xticks(range(0, int(lim)+1, lim // 20), fontsize=6, rotation=45)

ymax = plt.ylim()[1]
percentiles = {
    #'1%': p1,
    #'10%': p10,
    '50%': median,
    '90%': p90,
    '99%': p99,
}

#print percentiles to std
print(f"Percentiles for {args.feature} in {args.title}:")
for label, value in percentiles.items():
    print(f"{label}: {value:.2f}")

for label, x in percentiles.items():
    plt.axvline(x, color='black', linestyle='--', linewidth=1)
    plt.text(x, ymax * 0.75, label, rotation=90, va='top', ha='right', fontsize=8, color='black')

plt.savefig('./' + args.input.split('/')[-1].split('.')[0] + '_' + args.feature + '.svg', format='svg')