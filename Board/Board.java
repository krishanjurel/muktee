import edu.princeton.cs.algs4.In;

import java.util.Comparator;
import java.util.Iterator;
import java.util.Vector;

public class Board {

    /* local copy of tiles */
    private int[][] tiles;
    private int size;

    private Vector<Board> neighborBoards;

    // create a board from an n-by-n array of tiles,
    // where tiles[row][col] = tile at (row, col)
    public Board(int[][] tiles) {
        size = tiles.length;
        this.tiles = new int[tiles.length][tiles.length];
        for (int row = 0; row < tiles.length; row++) {
            for (int col = 0; col < tiles.length; col++)
                this.tiles[row][col] = tiles[row][col];
        }
        neighborBoards = new Vector<Board>();
    }

    // string representation of this board
    public String toString() {
        String string = Integer.toString(size) + "\n";
        for (int row = 0; row < size; row++) {
            for (int col = 0; col < size; col++) {
                string = " " + string.concat(Integer.toString(tiles[row][col])) + " ";
            }
            string = string.concat("\n");
        }
        return string;
    }

    private Board(int size) {
        int row = 0, col = 0;
        tiles = new int[size][size];
        for (row = 0; row < size; row++) {
            for (col = 0; col < size; col++) {
                tiles[row][col] = (row * size + col);
            }
        }
        /*set the last column to be zero */
        tiles[row - 1][col - 1] = 0;
    }

    private int BlankTile() {
        boolean _break = false;
        int row = 0, col = 0;
        for (row = 0; row < size; row++) {
            for (col = 0; col < size; col++) {
                if (tiles[row][col] == 0) {
                    _break = true;
                    break;
                }
            }
            if (_break)
                break;

        }
        return row * size + col;
    }

    private Vector<Integer> Neighbors() {
        boolean _break = false;
        Vector<Integer> neighs = new Vector<Integer>();
        int row = 0, col = 0;
        for (row = 0; row < size; row++) {
            for (col = 0; col < size; col++) {
                if (tiles[row][col] == 0) {
                    _break = true;
                    break;
                }
            }
            /* if inner loop is broken */
            if (_break)
                break;
        }

        /* first row with atleast two rows */
        if (row == 0 && (row + 1) < size) {
            neighs.add((row + 1) * size + col);
        }
        /*last row, with atleast two rows */
        if ((row + 1) == size && row != 0) {
            neighs.add((row - 1) * size + col);
        }

        /* some where in the middle */
        if (row > 0 && (row + 1) < size) {
            neighs.add((row + 1) * size + col);
            neighs.add((row - 1) * size + col);
        }

        /*first columns, with atleast 2 columns */
        if (col == 0 && (col + 1) < size) {
            neighs.add(row * size + col + 1);
        }
        /*last columns with at least 2 columns */
        if ((col + 1) == size && col != 0) {
            neighs.add(row * size + col - 1);
        }

        /* some where in the middle */
        if (col > 0 && (col + 1) < size) {
            neighs.add(row * size + col - 1);
            neighs.add(row * size + col + 1);
        }

        //System.out.println("Neighbours of " + toString() + " are " + Integer.toString(neighs.size()));
        //System.out.println("Neighbours " + Integer.toString(neighs.size()));

        return neighs;
    }

    // board dimension n
    public int dimension() {
        return size;
    }

    private int ManDist(int val, int _exp) {
        /*handle special case */
        if (val == 0) val = _exp = 1;

        val = val - 1;
        _exp = _exp - 1;

        int row = val / size;
        int col = val % size;
        int _row = _exp / size;
        int _col = _exp % size;
        return Math.abs(row - _row) + Math.abs(col - _col);
    }


    // number of tiles out of place
    public int hamming() {
        int dist = 0;
        int row = 0, col = 0;
        for (row = 0; row < size; row++) {
            for (col = 0; col < size; col++) {
                if (ManDist(tiles[row][col], row * size + col + 1) != 0)
                    ++dist;
            }
        }
        return dist;
    }

    // sum of Manhattan distances between tiles and goal
    public int manhattan() {
        int dist = 0;
        int row = 0, col = 0;
        for (row = 0; row < size; row++) {
            for (col = 0; col < size; col++) {
                dist += ManDist(tiles[row][col], row * size + col + 1);
            }
        }
        return dist;
    }

    // is this board the goal board?
    public boolean isGoal() {
        return manhattan() == 0;
    }

    // does this board equal y?
    public boolean equals(Object y) {
        boolean same = true;
        int row = 0, col = 0;
        Board board = (Board) y;

        for (row = 0; row < size; row++) {
            for (col = 0; col < size; col++) {
                if (tiles[row][col] != board.tiles[row][col]) {
                    same = false;
                    break;
                }
            }
        }
        return same;
    }

    private class BoardIterator implements Iterator<Board> {

        int totalN = 0;
        int _i = 0;


        /**
         * take the current boards tiles and then
         * construct neighours.
         */
        private BoardIterator() {
            int row = 0, col = 0;
            int _row = 0, _col = 0;
            int blankTile = BlankTile();
            _row = blankTile / size;
            _col = blankTile % size;
            neighborBoards = new Vector<Board>();
            Vector<Integer> neighs = Neighbors();
            totalN = neighs.size();
            for (int i = 0; i < totalN; i++) {
                row = neighs.get(i) / size;
                col = neighs.get(i) % size;
                /* create a new board with existing tiles */
                Board board = new Board(tiles);
                int temp = board.tiles[row][col];
                /*set the element at i to zero */
                board.tiles[row][col] = 0;
                board.tiles[_row][_col] = temp;
                /* add this board into the neighbors */
                neighborBoards.add(board);
            }
        }

        public boolean hasNext() {
            return _i < neighborBoards.size();
        }

        public Board next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            return neighborBoards.get(_i++);
        }
    }


    // all neighboring boards
    public Iterable<Board> neighbors() {
        return new Iterable<Board>() {
            public Iterator<Board> iterator() {
                return new BoardIterator();
            }
        };
    }

    private class BoardComparator implements Comparator<Board> {
        public int compare(Board board1, Board board2) {
            int distboard1 = board1.manhattan();
            int distboard2 = board2.manhattan();
            return Integer.compare(distboard1, distboard2);
        }
    }

    private Comparator<Board> comparator() {
        return new BoardComparator();
    }

    // a board that is obtained by exchanging any pair of tiles
    public Board twin() {
        return this;
    }

    // unit testing (not graded)
    public static void main(String[] args) {

        In in = new In(args[0]);
        int n = in.readInt();
        System.out.println("the size of the matrix " + n);
        int[][] tiles = new int[n][n];
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                tiles[i][j] = in.readInt();

        System.out.println("tiles size " + tiles.length);

        Board board = new Board(tiles);
        System.out.println(board.toString());
        System.out.println(board.manhattan());

        Iterable<Board> boards = board.neighbors();

        for (Board _board : boards) {
            System.out.println(_board.toString());
            System.out.println("manhattan distance " + _board.manhattan());
            System.out.println("hamming distance " + _board.hamming());

        }
    }
}
