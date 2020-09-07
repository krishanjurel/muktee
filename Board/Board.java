import edu.princeton.cs.algs4.In;

import java.util.Comparator;
import java.util.Iterator;
import java.util.Vector;


public class Board {

    /* local copy of tiles */
    private int[][] tiles;
    private int row, col;


    // create a board from an n-by-n array of tiles,
    // where tiles[row][col] = tile at (row, col)
    public Board(int[][] tiles) {
        if (tiles == null) throw new java.lang.IllegalArgumentException();

        row = tiles.length;
        col = tiles[0].length;
        this.tiles = new int[row][col];
        for (int r = 0; r < row; r++) {
            for (int c = 0; c < col; c++)
                this.tiles[r][c] = tiles[r][c];
        }
    }

    // string representation of this board
    public String toString() {
        String string = Integer.toString(row) + "\n";
        for (int r = 0; r < row; r++) {
            for (int c = 0; c < col; c++) {
                string = " " + string.concat(Integer.toString(tiles[r][c])) + " ";
            }
            string = string.concat("\n");
        }
        return string;
    }


    private int BlankTile() {
        boolean _break = false;
        int r = 0, c = 0;
        for (r = 0; r < row; r++) {
            for (c = 0; c < col; c++) {
                if (tiles[r][c] == 0) {
                    _break = true;
                    break;
                }
            }
            if (_break)
                break;

        }
        return r * row + c;
    }


    // board dimension n
    public int dimension() {
        return row;
    }

    private int ManDist(int val, int _exp) {
        /*handle special case */
        if (val == 0) val = _exp = 1;

        val = val - 1;
        _exp = _exp - 1;

        int r = val / row;
        int c = val % col;
        int _row = _exp / row;
        int _col = _exp % col;
        return Math.abs(r - _row) + Math.abs(c - _col);
    }


    // number of tiles out of place
    public int hamming() {
        int dist = 0;
        int r = 0, c = 0;
        for (r = 0; r < row; r++) {
            for (c = 0; c < col; c++) {
                if (ManDist(tiles[r][c], r * row + c + 1) != 0)
                    ++dist;
            }
        }
        return dist;
    }

    // sum of Manhattan distances between tiles and goal
    public int manhattan() {
        int dist = 0;
        int r = 0, c = 0;
        for (r = 0; r < row; r++) {
            for (c = 0; c < col; c++) {
                dist += ManDist(tiles[r][c], r * row + c + 1);
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
        int r = 0, c = 0;

        if (this == y)
            return true;

        if (!(y instanceof Board)) {
            return false;
        }

        if (y == null) {
            return false;
        }
        Board board = (Board) y;
        /* if is off different dimensions */
        if (same == true &&
                (this.row != board.row ||
                        this.col != board.col)) {
            same = false;
        }
        if (same == true) {
            for (r = 0; r < row; r++) {
                for (c = 0; c < col; c++) {
                    if (tiles[r][c] != board.tiles[r][c]) {
                        same = false;
                        break;
                    }
                }
            }
        }
        return same;
    }

    private class BoardIterator implements Iterator<Board> {

        int totalN = 0;
        int _i = 0;
        private Vector<Board> neighborBoards;

        /**
         * take the current boards tiles and then
         * construct neighours.
         */
        private BoardIterator() {
            int r = 0, c = 0;
            int _row = 0, _col = 0;
            int blankTile = BlankTile();
            _row = blankTile / row;
            _col = blankTile % col;
            neighborBoards = new Vector<Board>();
            Vector<Integer> neighs = Neighbors();
            totalN = neighs.size();
            for (int i = 0; i < totalN; i++) {
                r = neighs.get(i) / row;
                c = neighs.get(i) % col;
                /* create a new board with existing tiles */
                Board board = new Board(tiles);
                int temp = board.tiles[r][c];
                /*set the element at i to zero */
                board.tiles[r][c] = 0;
                board.tiles[_row][_col] = temp;
                /* add this board into the neighbors */
                neighborBoards.add(board);
            }
        }

        private Vector<Integer> Neighbors() {
            boolean _break = false;
            Vector<Integer> neighs = new Vector<Integer>();
            int r = 0, c = 0;
            for (r = 0; r < row; r++) {
                for (c = 0; c < col; c++) {
                    if (tiles[r][c] == 0) {
                        _break = true;
                        break;
                    }
                }
                /* if inner loop is broken */
                if (_break)
                    break;
            }

            /* first row with atleast two rows */
            if (r == 0 && (r + 1) < row) {
                neighs.add((r + 1) * row + c);
            }
            /*last row, with atleast two rows */
            if ((r + 1) == row && r != 0) {
                neighs.add((r - 1) * row + c);
            }

            /* some where in the middle */
            if (r > 0 && (r + 1) < row) {
                neighs.add((r + 1) * row + c);
                neighs.add((r - 1) * row + c);
            }

            /*first columns, with atleast 2 columns */
            if (c == 0 && (c + 1) < col) {
                neighs.add(r * row + c + 1);
            }
            /*last columns with at least 2 columns */
            if ((c + 1) == col && c != 0) {
                neighs.add(r * row + c - 1);
            }

            /* some where in the middle */
            if (c > 0 && (c + 1) < col) {
                neighs.add(r * row + c - 1);
                neighs.add(r * row + c + 1);
            }

            //System.out.println("Neighbours of " + toString() + " are " + Integer.toString(neighs.size()));
            //System.out.println("Neighbours " + Integer.toString(neighs.size()));

            return neighs;
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


    // a board that is obtained by exchanging any pair of tiles
    public Board twin() {
        int row1, col1;

        /* get the blank tile index */
        int idx = BlankTile();
        int r = idx / row;
        int c = idx % col;

        /* see which side we can swap elements */
        if (r + 1 < row) {
            /* take from next row */
            row1 = r + 1;
        } else if (r - 1 >= 0) {
            /* or one top row */
            row1 = r - 1;
        } else {
            /* this should never happen as a board can not be single row */
            row1 = r;
        }

        c = 0;
        col1 = 1;

        int[][] _tiles = new int[row][col];
        /* copy the tiles */
        for (int i = 0; i < row; i++) {
            for (int j = 0; j < col; j++)
                _tiles[i][j] = tiles[i][j];
        }

        int temp = _tiles[row1][col1];
        _tiles[row1][col1] = _tiles[row1][c];
        _tiles[row1][c] = temp;
        return new Board(_tiles);
    }

    // unit testing (not graded)
    public static void main(String[] args) {

        In in = new In(args[0]);
        int n = in.readInt();
        System.out.println("the size of the matrix " + n);
        int[][] tiles = new int[4][5];
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                tiles[i][j] = in.readInt();

        System.out.println("tiles size " + tiles[2].length);

        Board board = new Board(tiles);


        System.out.println("board \n" + board.toString());
        System.out.println("twin \n" + board.twin());
        System.out.println(board.manhattan());

        Iterable<Board> boards = board.neighbors();

        for (Board _board : boards) {
            System.out.println(_board.toString());
            System.out.println("manhattan distance " + _board.manhattan());
            System.out.println("hamming distance " + _board.hamming());

        }
    }
}
