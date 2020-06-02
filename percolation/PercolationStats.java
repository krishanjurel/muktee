/* *****************************************************************************
 *  Name:
 *  Date:
 *  Description:
 **************************************************************************** */

import edu.princeton.cs.algs4.StdRandom;
import edu.princeton.cs.algs4.StdStats;

public class PercolationStats {
    private int trials;
    private double[] means;
    private int opened;
    private final double CONFIDENCE_95 = 1.96;

    // perform independent trials on an n-by-n grid
    public PercolationStats(int n, int trials) {
        if (n <= 0 || trials <= 0) throw new IllegalArgumentException();
        means = new double[trials];
        this.trials = trials;

        for (int i = 0; i < trials; i++) {
            //System.out.println("Trials: " + (i + 1) + "/" + trials);
            means[i] = 0;
            opened = 0;
            Percolation perc = new Percolation(n);
            while (opened < (n * n)) {
                int row = StdRandom.uniform(1, n + 1);
                int col = StdRandom.uniform(1, n + 1);
                //System.out.println("Open row:col " + row + ":" + col);
                perc.open(row, col);
                opened = perc.numberOfOpenSites();
                if (perc.percolates()) {
                    means[i] = (double) opened / (n * n);
                    break;
                }
            }
        }
    }

    // sample mean of percolation threshold
    public double mean() {
        return StdStats.mean(means);
    }


    // sample standard deviation of percolation threshold
    public double stddev() {
        return StdStats.stddev(means);
    }

    // low endpoint of 95% confidence interval
    public double confidenceLo() {

        return mean() - (CONFIDENCE_95 * stddev()) / Math.sqrt(trials);
    }

    // high endpoint of 95% confidence interval
    public double confidenceHi() {
        return mean() + (CONFIDENCE_95 * stddev()) / Math.sqrt(trials);

    }


    public static void main(String[] args) {
        int n = Integer.parseInt(args[0]);
        int trials = Integer.parseInt(args[1]);
        PercolationStats percolationStats = new PercolationStats(n, trials);
        //System.out.println("Mean: " + percolationStats.mean());
        //System.out.println("stddev :" + percolationStats.stddev());
        //System.out.println("lo confidenece :" + percolationStats.confidenceLo());
        //System.out.println("Hi confidenece :" + percolationStats.confidenceHi());
    }
}
