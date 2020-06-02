/* *****************************************************************************
 *  Name: krishan
 *  Date: 14 May 2020
 *  Description: Monte Carlo percolation simulation
 **************************************************************************** */

public class Percolation {
    /* identifier of every node */
    private static int siteOpen = 1;
    private static int siteClose = 0;


    private int[] id;
    private int[] sz;
    private int[] sites;
    private int[] root;
    private int openSites;
    private int n;
    private int index;
    private int topIndex;
    private int leftIndex;
    private int rightIndex;

    /* constructor */
    public Percolation(int n) {

        if (n <= 0) throw new IllegalArgumentException();
        this.n = n;
        openSites = 0;
        index = 0;


        id = new int[n * n];
        sites = new int[n * n];
        sz = new int[n * n];
        root = new int[n * n];
        for (int i = 0; i < n * n; i++) {
            id[i] = i;
            sites[i] = siteClose;
            sz[i] = 1;
            root[i] = i;
        }
    }


    /* find the root */
    private int findRoot(int i) {
        //System.out.print("findRoot of i " + i);
        while (i != id[i]) i = id[i];
        //System.out.println(" is " + i);
        return i;
    }

    private int getTopIndex(int row, int col) {
        topIndex = -1;
        if (row - 1 >= 1) {
            topIndex = (row - 2) * n + col - 1;
        }
        //System.out.println("row:col:topIndex " + row + ":" + col + ":" + topIndex);
        return topIndex;
    }

    private int getBelowIndex(int row, int col) {
        int belowIndex = -1;
        if (row + 1 <= n) {
            belowIndex = row * n + col - 1;
        }
        //System.out.println("row:col:bleowIndex " + row + ":" + col + ":" + belowIndex);
        return belowIndex;
    }

    private int getLeftIndex(int row, int col) {
        leftIndex = -1;
        if (col - 1 >= 1) {
            leftIndex = (row - 1) * n + col - 2;
        }
        //System.out.println("row:col:leftIndex " + row + ":" + col + ":" + leftIndex);
        return leftIndex;
    }

    private int getRightIndex(int row, int col) {
        rightIndex = -1;
        if (col + 1 <= n) {
            rightIndex = (row - 1) * n + col;
        }
        //System.out.println("row:col:rightIndex " + row + ":" + col + ":" + rightIndex);
        return rightIndex;
    }

    private int getCurrentIndex(int row, int col) {
        return (row - 1) * n + col - 1;
    }


    private void connectHorizontal(int row, int col) {
        //String nameofCurrMethod = new Exception().getStackTrace()[0]
        //        .getMethodName();
        // System.out.println(nameofCurrMethod);
        int leftRoot = -1;
        int rightRoot = -1;
        index = getCurrentIndex(row, col);
        id[index] = index;
        leftIndex = getLeftIndex(row, col);
        rightIndex = getRightIndex(row, col);

        if (leftIndex != -1 && sites[leftIndex] == siteOpen) {
            leftRoot = findRoot(leftIndex);
            //leftRoot = root[leftIndex];
        }
        if (rightIndex != -1 && sites[rightIndex] == siteOpen) {
            rightRoot = findRoot(rightIndex);
            //rightRoot = root[rightIndex];
        }

        /* case first, when the left root is connected at
            to the top.
         */
        if (leftRoot >= 0 && leftRoot < n) {
            sz[leftRoot] += 1;
            id[index] = leftIndex;

            if (rightRoot != -1 && rightRoot != leftRoot) {
                sz[leftRoot] += sz[rightRoot];
                id[rightRoot] = leftRoot;
                root[rightRoot] = leftRoot;
            }
            root[index] = leftRoot;
        }
        else if (rightRoot >= 0 && rightRoot < n) {
            sz[rightRoot] += 1;
            id[index] = rightIndex;

            if (leftRoot != -1 && rightRoot != leftRoot) {
                sz[rightRoot] += sz[leftRoot];
                id[leftRoot] = rightRoot;
                root[leftRoot] = rightRoot;
            }
            root[index] = rightRoot;
        }

        /* still not connected */
        if (id[index] == index) {

            if (leftRoot != -1) {
                sz[leftRoot] += 1;
                id[index] = leftIndex;
                root[index] = leftRoot;
            }

            if (rightRoot != -1 && leftRoot != rightRoot) {
                sz[index] += sz[rightRoot];
                id[rightRoot] = index;
                root[rightRoot] = index;
            }
        }

        /* process all connected elements to the right of the current
         * element
         **/
        /*
        for (int i = col; i <= n; i++) {
            rightIndex = getRightIndex(row, col);
            if (rightIndex == -1 || sites[rightIndex] == siteClose) {
                break;
            }
            int root1 = findRoot(index);
            int root2 = findRoot(rightIndex);
            //id[rightIndex] = rightIndex - 1;
            if (root2 < n && index >= n) {
                id[root1] = root2;
            }
            else {
                id[rightIndex] = rightIndex - 1;
            }
        }
         */
        //System.out.print("index:id[index]: ");
        //for (int i = 1; i <= n; i++) {
        //    index = getCurrentIndex(row, i);
        //    System.out.print(" " + index + ":" + id[index]);
        //}
        //System.out.println();
    }

    private void connectVertical(int row, int col) {
        int root1, root2;
        //String nameofCurrMethod = new Exception().getStackTrace()[0]
        //        .getMethodName();
        // System.out.println(nameofCurrMethod);
        root1 = -1;
        root2 = -1;
        index = getCurrentIndex(row, col);
        // id[index] = index;
        topIndex = getTopIndex(row, col);
        if (topIndex != -1 && sites[topIndex] == siteOpen) {

            // System.out.print("index : topIndex : root1 : root2 " + index + " : " + topIndex);
            root1 = findRoot(index);
            root2 = findRoot(topIndex);
            // System.out.println(" : " + root1 + " : " + root2);
            if (root1 < root2) {
                id[root2] = root1;
                root[topIndex] = root1;
                sz[root1] += sz[root2];
            }
            else if (root2 < root1) {
                id[root1] = root2;
                root[index] = root2;
                sz[root2] += sz[root1];
            }
        }

        int belowIndex = getBelowIndex(row, col);
        if (belowIndex != -1 && sites[belowIndex] == siteOpen) {


            //System.out.print("index : belowIndex : root1 : root2 " + index + " : " + belowIndex);
            root1 = findRoot(index);
            root2 = findRoot(belowIndex);
            //System.out.println(" : " + root1 + " : " + root2);
            if (root1 < root2) {
                id[root2] = root1;
                root[belowIndex] = root1;
                sz[root1] += sz[root2];
            }
            else if (root2 < root1) {
                id[root1] = root2;
                root[index] = root2;
                sz[root2] += sz[root1];
            }
        }
    }

    /* opening a site */
    public void open(int row, int col) {
        //String nameofCurrMethod = new Exception().getStackTrace()[0]
        //       .getMethodName();
        // System.out.println(nameofCurrMethod + "row:col " + row + ":" + col);

        if (row > n || col > n) throw new IllegalArgumentException();
        if (row <= 0 || col <= 0) throw new IllegalArgumentException();
        index = getCurrentIndex(row, col);

        /* do nothing if site is already open */
        if (sites[index] == siteOpen)
            return;

        if (sites[index] != siteOpen) {
            sites[index] = siteOpen;
            openSites++;
        }
        connectHorizontal(row, col);
        connectVertical(row, col);
    }

    /* return the site's open status */
    public boolean isOpen(int row, int col) {
        //String nameofCurrMethod = new Exception().getStackTrace()[0]
        //        .getMethodName();
        //  System.out.println(nameofCurrMethod + "row:col " + row + ":" + col);

        if (row > n || col > n) throw new IllegalArgumentException();
        if (row <= 0 || col <= 0) throw new IllegalArgumentException();

        index = getCurrentIndex(row, col);
        return sites[index] == siteOpen;
    }

    public boolean isFull(int row, int col) {
        int root = n;
        //String nameofCurrMethod = new Exception().getStackTrace()[0]
        //        .getMethodName();
        // System.out.println(nameofCurrMethod + "row:col " + row + ":" + col);

        if (row > n || col > n) throw new IllegalArgumentException();
        if (row <= 0 || col <= 0) throw new IllegalArgumentException();

        index = getCurrentIndex(row, col);
        if (sites[index] == siteOpen) {
            root = findRoot(index);
        }
        return root < n;
    }

    public int numberOfOpenSites() {
        return openSites;
    }

    /* a system percolates if the the root of the
       the lowest site is a site from the top row
     */
    public boolean percolates() {
        boolean connected = false;
        int belowIndex = 0;
        /* a system percolates if the any item at the bottom site
           is connected with the top sites
         */
        int row, col;
        for (row = n; row <= n; row++) {
            for (col = 1; col <= n; col++) {
                connected = isFull(row, col);
                if (connected)
                    break;
            }
        }
        return connected;
    }
}



