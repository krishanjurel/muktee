import edu.princeton.cs.algs4.In;
import edu.princeton.cs.algs4.MinPQ;

import java.util.Iterator;
import java.util.Vector;


public class Solver {
    /* number of moves */
    private int _moves = 0;
    /* initial priority queue */
    private MinPQ<BoardPriority> pq;
    private Vector<BoardPriority> sq;
    final private int max_moves = 100000000;


    private class BoardPriority implements Comparable<BoardPriority> {
        private Board board;
        private int moves;
        private int dist;
        private int hamdist;
        private BoardPriority prev;


        BoardPriority(Board board, int moves) {
            this.board = board;
            this.dist = board.manhattan();
            this.moves = moves;
            this.hamdist = board.hamming();
            this.prev = null;
        }

        BoardPriority(Board board, int moves, BoardPriority prev) {
            this.board = board;
            this.dist = board.manhattan();
            this.moves = moves;
            this.hamdist = board.hamming();
            this.prev = prev;
        }

        public Iterable<Board> neighbors() {
            return board.neighbors();
        }

        public int getMoves() {
            return moves;
        }

        public int getDist() {
            return dist;
        }

        public Board getBoard() {
            return board;
        }

        public int getPrio() {
            return dist + moves;
        }

        public int compareTo(BoardPriority b2) {
            int ret;
            int prio1 = this.getPrio(), prio2 = b2.getPrio();
            if (prio1 == prio2) {
                prio1 = this.dist;
                prio2 = b2.dist;
            }
            ret = Integer.compare(prio1, prio2);
            //System.out.println("compTo dist/moves b1:b2  ret " + this.dist + "/" + this.moves + ":" + b2.dist + "/" + b2.moves + " " + ret);
            return ret;
        }
    }

    /**
     * final solution queue, keep add elements in it
     * the ones that have been removed/
     */

    /* implement the Astar algo */
    private void AStar() {
        /*remove the least priroty queue*/
        /*delete the lowest priority queue */
        while (_moves < max_moves) {
            BoardPriority boardPriority = pq.delMin();
            //System.out.println("Dequed board dist/moves " + boardPriority.dist + "/" + boardPriority.moves);
            /* if we find the goal */
            sq.add(boardPriority);

            if (boardPriority.getBoard().isGoal() == true)
                break;

            _moves = boardPriority.moves + 1;
            Iterable<Board> neighs = boardPriority.neighbors();
            //System.out.println("******************************************");
            for (Board _board : neighs) {
                boolean dup = false;
                Iterator<BoardPriority> itr = sq.iterator();
                /* check out if _board is in the solution queue */
                /* if the next node is previously searche node */
                while (itr.hasNext() == true) {
                    Board _brd = itr.next().getBoard();
                    if (_brd.equals(_board) == true) {
                        dup = true;
                        break;
                    }
                }

                if (!dup) {
                    BoardPriority boardPriority_ = new BoardPriority(_board, _moves, boardPriority);
                    pq.insert(boardPriority_);
                    //System.out.println("Astar Enqued board dist/moves " + boardPriority.dist + "/" + boardPriority.moves);
                }
            }
        }
        return;
    }


    // find a solution to the initial board (using the A* algorithm)
    public Solver(Board initial) {
        _moves = 0;

        BoardPriority boardPriority = new BoardPriority(initial, _moves, null);
        pq = new MinPQ<BoardPriority>();
        sq = new Vector<BoardPriority>();
        /*insert the first element in the queue*/
        Iterable<Board> neighs = initial.neighbors();
        sq.add(boardPriority);
        _moves++;
        //pq.insert(new BoardPriority(initial, _moves));
        //System.out.println("******************************************");
        for (Board board : neighs) {
            //System.out.println("Enqued board man-dist: moves " + board.hamming() + ":" + _moves);
            BoardPriority boardPriority_ = new BoardPriority(board, _moves, boardPriority);
            pq.insert(boardPriority_);
            //System.out.println("Solver Enqued board dist/moves " + boardPriority.getDist() + "/" + boardPriority.getMoves());
        }
        AStar();
    }

    // is the initial board solvable? (see below)
    public boolean isSolvable() {
        return false;
    }

    // min number of moves to solve initial board; -1 if unsolvable
    public int moves() {
        return _moves;
    }

    private class SolverIterator implements Iterator<Board> {
        private int totalN = _moves;
        private int _current = 0;
        private BoardPriority lastParent;
        private Board _brd;

        private SolverIterator() {
            //System.out.println(" totalN " + totalN);
            lastParent = sq.lastElement();

        }

        public boolean hasNext() {
            return lastParent != null;
        }

        public Board next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            _brd = lastParent.getBoard();
            lastParent = lastParent.prev;
            _current++;
            return _brd;
        }
    }

    private Iterator<Board> iteratr() {
        return new SolverIterator();
    }


    // sequence of boards in a shortest solution; null if unsolvable
    public Iterable<Board> solution() {
        return new Iterable<Board>() {
            public Iterator<Board> iterator() {
                return new SolverIterator();
            }
        };
    }

    // test client (see below)
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

        Solver solver = new Solver(new Board(tiles));
        if (solver.isSolvable())
            System.out.println("solution is solvable");

        System.out.println("total moves " + solver.moves());

        Iterator<Board> itr = solver.iteratr();
        while (itr.hasNext() == true) {
            Board _board = itr.next();
            System.out.println(_board.toString());
        }
    }
}
