/* *****************************************************************************
 *  Name: krishan
 *  Date: 14 May 2020
 *  Description: Monte Carlo percolation simulation, requires algs4.jar java package
 *
 *  This is part of the algorithms course from coursera (Princeton University).
 *  Use the test text files for testing with the provided java program of PercolationVisualizer.java
 *
 *
 **************************************************************************** */

public class Percolation {
    /* identifier of every node */
    final static int siteOpen = 1;
    final static int siteClose = 0;


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
        while (i != id[i]) i = id[i];
        return i;
    }

    private int getTopIndex(int row, int col) {
        topIndex = -1;
        if (row - 1 >= 1) {
            topIndex = (row - 2) * n + col - 1;
        }
        return topIndex;
    }

    private int getBelowIndex(int row, int col) {
        int belowIndex = -1;
        if (row + 1 <= n) {
            belowIndex = row * n + col - 1;
        }
        return belowIndex;
    }

    private int getLeftIndex(int row, int col) {
        leftIndex = -1;
        if (col - 1 >= 1) {
            leftIndex = (row - 1) * n + col - 2;
        }
        return leftIndex;
    }

    private int getRightIndex(int row, int col) {
        rightIndex = -1;
        if (col + 1 <= n) {
            rightIndex = (row - 1) * n + col;
        }
        return rightIndex;
    }

    private int getCurrentIndex(int row, int col) {
        return (row - 1) * n + col - 1;
    }

    private void quickUnion(int p, int q) {
        int rootp = findRoot(p);
        int rootq = findRoot(q);

        if (rootp == rootq) return;

        id[rootp] = rootq;
        return;
    }

    private void quickWeightedUnion(int p, int q) {
        int rootp = findRoot(p);
        int rootq = findRoot(q);

        if (rootp == rootq) return;

        /* compare the size of the size of the tree, and add the node to
           the bigger tree
         */
        if (sz[rootp] > sz[rootq]) {
            sz[rootp] += sz[rootq];
            id[rootq] = rootp;
        } else {
            sz[rootq] += sz[rootp];
            id[rootp] = rootq;
        }
    }

    // generic connect method of node p connecting to node q
    private void connect(int p, int q) {
        //quickWeightedUnion(p, q);
        quickUnion(p, q);
    }

    private void connect(int row, int col, boolean qwf) {

        int leftRoot = -1;
        int rightRoot = -1;
        int topRoot = -1;
        int belowRoot = -1;
        int belowIndex = -1;
        int tempIndex = -1;
        index = getCurrentIndex(row, col);
        leftIndex = getLeftIndex(row, col);
        rightIndex = getRightIndex(row, col);
        topIndex = getTopIndex(row, col);
        belowIndex = getBelowIndex(row, col);

        /*default current node is connected to itself */
        id[index] = index;

        /* first connect the elements on the horizontal axis, followed by vertical axis.
            Connect to the tree with largest size with overriding factor is always connect
            to the node that is connected to the top row.
         */

        /*find the roots of left, right, top and bottom open sites */
        tempIndex = leftIndex;
        if (tempIndex >= 0 && sites[tempIndex] == siteOpen)
            leftRoot = findRoot(tempIndex);

        tempIndex = rightIndex;
        if (tempIndex >= 0 && sites[tempIndex] == siteOpen)
            rightRoot = findRoot(tempIndex);

        tempIndex = topIndex;
        if (tempIndex >= 0 && sites[tempIndex] == siteOpen)
            topRoot = findRoot(tempIndex);

        tempIndex = belowIndex;
        if (tempIndex >= 0 && sites[tempIndex] == siteOpen)
            belowRoot = findRoot(tempIndex);


        /************************************set the horizontal nodes ******************/
        /* case 1, if left node is connected to top row, connect the
         * the current node to left node*/
        if (leftRoot >= 0 && leftRoot < n) {
            //connect(index, leftIndex
            connect(index, leftRoot);
            /*now check whether we should connect the right node of current node to
              add into this tree
             */
            if (rightRoot >= 0)
                //connect(rightIndex, index) // use the below call for fast connection
                connect(rightRoot, leftRoot);
        }

        /* case 2, if right node is connected to the top row, connect the current
           node to the top row, its possible that the right node is already part of the
           same tree as current node. but the connect call handles that gracefully
         */
        if (rightRoot >= 0 && rightRoot < n) {
            //connect(index, rightIndex
            connect(index, rightRoot);
            /*now check whether we should connect the right node of current node to
              add into this tree
             */
            if (leftRoot >= 0)
                //connect(index, rightIndex) // use the below call for fast connection
                connect(leftRoot, rightRoot);
        }

        /* case 3, top and left both are not connected to the top row, then
            connect the current node to the left node and right node to current node
         */
        if (id[index] == index) {
            if (leftRoot >= 0)
                connect(index, leftRoot);

            if (rightRoot >= 0)
                connect(rightRoot, index);
        }
        /************************************horizontal is done ******************/

        /************************************set the vertical nodes ******************/
        /*read the root of the current node */
        int currentRoot = findRoot(index);

        /* if top site is open, connect the node having lowest root */
        if (topRoot >= 0) {
            if (currentRoot < topRoot)
                connect(topRoot, currentRoot);
            else
                connect(currentRoot, topRoot);
        }

        currentRoot = findRoot(index);

        /* if top site is open, connect the node having lowest root */
        if (belowRoot >= 0) {
            if (currentRoot < belowRoot)
                connect(belowRoot, currentRoot);
            else
                connect(currentRoot, belowRoot);
        }
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
        } else if (rightRoot >= 0 && rightRoot < n) {
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
            } else if (root2 < root1) {
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
            } else if (root2 < root1) {
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
        //connectHorizontal(row, col);
        //connectVertical(row, col);
        connect(row, col, true);
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



