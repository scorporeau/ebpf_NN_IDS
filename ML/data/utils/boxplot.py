import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument('--inputs', nargs='+', type=str, default=['../self/logs/2026-04-17/net_listener_tc.csv'], help='one or more input CSV files with the same columns')
parser.add_argument('--feature', type=str, default='time_parsing', help='feature to plot (must exactly match column name in CSV)')
parser.add_argument('--labels', type=bool, default=True, help='enable title, axis labels, tick labels, and legend')
args = parser.parse_args()


feature_data = []
labels = []

for input_path in args.inputs:

    df = pd.read_csv(input_path, sep=',', usecols=[args.feature])

    #drop NaN rows & register features
    series = df.iloc[:, 0].dropna()
    feature_data.append(series)
    labels.append(input_path.split('/')[-1].replace('net_listener', '').replace('.csv', '').replace('_', ' '))


plt.figure(figsize=(12, 6))
# whis=[0, 100] makes whiskers extend from min (0th percentile) to max (100th percentile)
# patch_artist=True enables colored boxes
box = plt.boxplot(
    feature_data,
    labels=labels if args.labels else None,
    whis=[1, 99],  # Whiskers at 99th/1st percentiles instead of 1.5*IQR
    patch_artist=True,
    showfliers=False  # Hide outliers for cleaner visualization
)

# Add horizontal gridlines for easier value reading
plt.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.7)

# Set y-axis to logarithmic scale
plt.yscale('log')

#labels
if args.labels:
    unit = ''
    if 'time' in args.feature.lower():
        unit = ' (ns)'
    plt.title(f'Boxplot comparison of {args.feature}{unit}', fontsize=14, fontweight='bold')
    plt.xlabel('Dataset', fontsize=12)
    plt.ylabel(args.feature + unit, fontsize=12)
    
    # Add value annotations on each boxplot
    for i, series in enumerate(feature_data):
        q1 = series.quantile(0.25)
        median = series.quantile(0.5)
        q3 = series.quantile(0.75)
        min_val = series.quantile(0.1)
        max_val = series.quantile(0.99)
        
        # Position text annotations slightly offset from box position (i+1)
        x_pos = i + 1.25
        y_offset = max_val * 0.02
        
        # Draw small horizontal lines and text for key values
        plt.text(x_pos - 0.1, min_val, f'1%: {min_val:.0f}', fontsize=6, va='center')
        plt.text(x_pos, q1, f'25%: {q1:.0f}', fontsize=6, va='center')
        plt.text(x_pos, median, f'M: {median:.0f}', fontsize=6, va='center', fontweight='bold', color='red')
        plt.text(x_pos, q3, f'75%: {q3:.0f}', fontsize=6, va='center')
        plt.text(x_pos - 0.1 , max_val, f'99%: {max_val:.0f}', fontsize=6, va='center')

plt.tight_layout()
csv_path = './' + args.inputs[0].split('/')[-1].split('.')[0] + '_boxplot_' + args.feature + '.svg'
print(f'Saving boxplot under {csv_path}')
plt.savefig(csv_path, format='svg')