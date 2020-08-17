import edu.princeton.cs.algs4.In;
import edu.princeton.cs.algs4.MinPQ;

import java.util.Comparator;
import java.util.Iterator;
import java.util.Vector;


public class Solver {
    /* number of moves */
    private int _moves = 0;
    /* initial priority queue */
    private MinPQ<BoardPriority> pq;
    final private int max_moves = 100000000;

    private class BoardPriority implements Comparable<BoardPriority> {
        private Board board;
        private int moves;
        private int prio;
        private int hamdist;


        BoardPriority(Board board, int moves) {
            this.board = board;
            this.prio = board.manhattan() + moves;
            this.moves = moves;
            this.hamdist = board.hamming();

        }

        public Comparator<BoardPriority> boardPriorityComparator() {
            return new Comparator<BoardPriority>() {
                @java.lang.Override
                public int compare(BoardPriority b1, BoardPriority b2) {
                    int ret;
                    int prio1 = b1.prio, prio2 = b2.prio;
                    if (prio1 == prio2) {
                        prio1 = b1.prio - b1.moves;
                        prio2 = b2.prio - b2.moves;
                        //System.out.println("least moves b1:b2 " + prio1 + ":" + prio2);
                    }
                    ret = Integer.compare(prio1, prio2);
                    //System.out.println("comp prio b1:b2 " + prio1 + ":" + prio2 + " " + ret);
                    return ret;
                }
            };
        }

        public Iterable<Board> neighbors() {
            return board.neighbors();
        }

        public int getMoves() {
            return moves;
        }

        public Board getBoard() {
            return board;
        }

        public int getPrio() {
            return prio;
        }

        public Comparator<BoardPriority> comparator() {
            return boardPriorityComparator();
        }

        public int compareTo(BoardPriority b2) {
            int prio1 = this.prio, prio2 = b2.prio;
            if (prio1 == prio2) {
                prio1 = this.prio - this.moves;
                prio2 = b2.prio - b2.moves;
            }
            /*second attempt to break-tie*/
            if (prio1 == prio2) {
                prio1 = this.hamdist;
                prio2 = b2.hamdist;
            }
            return Integer.compare(prio1, prio2);
        }
    }

    /**
     * final solution queue, keep add elements in it
     * the ones that have been removed/
     */
    private Vector<Board> sq;

    /* implement the Astar algo */
    private void AStar() {
        /*remove the least priroty queue*/
        /*delete the lowest priority queue */
        while (_moves < max_moves) {
            BoardPriority boardPriority = pq.delMin();
            // System.out.println("******************************************");
            //System.out.println("dequed board priority " + board.manhattan());
            //System.out.println("dequed board priority " + boardPriority.getPrio());
            // System.out.println("Dequed board man-dist: moves " + boardPriority.board.manhattan() + ":" + boardPriority.moves);
            /* if we find the goal */
            sq.add(boardPriority.getBoard());
            _moves++;

            // System.out.println("sq size " + sq.size());

            if (boardPriority.getBoard().isGoal() == true)
                break;
            Iterable<Board> neighs = boardPriority.neighbors();
            //System.out.println("******************************************");
            for (Board _board : neighs) {
                boolean dup = false;
                Iterator<Board> itr = sq.iterator();
                Iterator<BoardPriority> bpitr = pq.iterator();
                /* check out if _board is in the solution queue */
                /* if the next node is previously searche node */
                while (itr.hasNext() == true) {
                    Board _brd = itr.next();
                    //System.out.println("deque board man-dist: moves " + _brd.manhattan() + ":" + _moves);
                    if (_brd.equals(_board) == true) {
                        dup = true;
                        break;
                    }
                }

                /* duplicate search node */
                while (dup == false && bpitr.hasNext() == true) {
                    Board _brd = bpitr.next().getBoard();
                    if (_brd.equals(_board) == true) {
                        //System.out.println("duplicate board man-dist: moves " + _board.hamming() + ":" + _moves);
                        dup = true;
                        break;
                    }
                }

                if (!dup) {
                    boardPriority = new BoardPriority(_board, _moves);
                    pq.insert(boardPriority);
                    //System.out.println("Astar Enqued board prio: moves " + boardPriority.getPrio() + ":" + boardPriority.getMoves());


                }
            }
        }
        return;
    }


    // find a solution to the initial board (using the A* algorithm)
    public Solver(Board initial) {
        _moves = 0;

        BoardPriority boardPriority = new BoardPriority(initial, _moves);
        pq = new MinPQ<BoardPriority>();
        sq = new Vector<Board>();
        /*insert the first element in the queue*/
        Iterable<Board> neighs = initial.neighbors();
        sq.add(initial);
        _moves++;
        //pq.insert(new BoardPriority(initial, _moves));
        //System.out.println("******************************************");
        for (Board board : neighs) {
            //System.out.println("Enqued board man-dist: moves " + board.hamming() + ":" + _moves);
            boardPriority = new BoardPriority(board, _moves);
            pq.insert(boardPriority);
            //System.out.println("Solver Enqued board prio: moves " + boardPriority.getPrio() + ":" + boardPriority.getMoves());
        }
        AStar();
    }

    // is the initial board solvable? (see below)
    public boolean isSolvable() {
        return sq.size() < max_moves;
    }

    // min number of moves to solve initial board; -1 if unsolvable
    public int moves() {
        return _moves;
    }

    private class SolverIterator implements Iterator<Board> {
        private int totalN = sq.size();
        private int _current = 0;
        private Iterator<Board> itr;

        private SolverIterator() {
            System.out.println(" totalN " + totalN);
            itr = sq.iterator();

        }

        public boolean hasNext() {
            return itr.hasNext();
        }

        public Board next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            return itr.next();
        }
    }


    // sequence of boards in a shortest solution; null if unsolvable
    public Iterable<Board> solution() {
        return new Iterable<Board>() {
            public Iterator<Board> iterator() {
                return new SolverIterator();
            }
        };
    }


    public Iterator<Board> iteratr() {
        return sq.iterator();
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

        /*
        Iterator<Board> itr = solver.iteratr();
        while (itr.hasNext() == true) {
            Board _board = itr.next();
            System.out.println(_board.toString());
        }

         */
    }
}
