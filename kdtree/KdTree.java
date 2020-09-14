import edu.princeton.cs.algs4.Point2D;
import edu.princeton.cs.algs4.RectHV;

import java.util.ArrayList;
import java.util.Iterator;


public class KdTree {

    private Node root;
    private final static int HORIZONTAL = 0;
    private final static int VERTICAL = 1;


    private class Node {
        private final double x;
        private final double y;
        private Node left, right;
        private int count;
        private int h; /* 0:horizontal (x) or 1: verticatl (y) */


        private Node(Point2D point, int h) {
            left = null;
            right = null;
            x = point.x();
            y = point.y();
            count = (root == null) ? 1 : 0;
            /* this would be the alterate of the previous */
            this.h = h;
        }


    }

    public KdTree()                               // construct an empty set of points
    {
        root = null;
    }

    public boolean isEmpty()                      // is the set empty?
    {
        return root == null;
    }


    private int size(Node node) {
        if (node == null) return 0;
        return node.count;
    }

    public int size()                         // number of points in the set
    {
        return size(root);
    }

    private int compareTo(double ths, double that) {
        int ret = 0;
        if (ths < that) ret = -1;
        else if (ths > that) ret = 1;
        else ret = 0;
        return ret;
    }

    private Node put(Node node, Point2D p, int h) {
        if (node == null) return new Node(p, h);

        double refkey, ptkey;
        /* the keys will be alternating */
        refkey = (node.h == HORIZONTAL) ? node.x : node.y;
        ptkey = (node.h == HORIZONTAL) ? p.x() : p.y();
        h = (node.h == HORIZONTAL) ? VERTICAL : HORIZONTAL;
        int cmp = compareTo(ptkey, refkey);
        if (cmp <= 0) node.left = put(node.left, p, h);
        else node.right = put(node.right, p, h);
        //if (cmp > 0) node.right = put(node.right, p, h);
        //else node.point = p;
        node.count += 1;
        return node;
    }


    public void insert(
            Point2D p)              // add the point to the set (if it is not already in the set)
    {
        if (p == null) throw new IllegalArgumentException();
        if (contains(p) == false)
            root = put(root, p, HORIZONTAL);
    }


    public boolean contains(Point2D p)            // does the set contain point p?
    {
        if (p == null) throw new IllegalArgumentException();
        Node node = root;
        int cmp = 0;
        double refkey, ptkey;
        boolean found = false;
        int h = HORIZONTAL;

        while (node != null && found == false) {
            /* the keys will be alternating */
            refkey = (node.h == HORIZONTAL) ? node.x : node.y;
            ptkey = (node.h == HORIZONTAL) ? p.x() : p.y();
            h = (node.h == HORIZONTAL) ? VERTICAL : HORIZONTAL;
            cmp = compareTo(ptkey, refkey);
            if (cmp <= 0) {
                if (p.compareTo(new Point2D(node.x, node.y)) == 0) {
                    found = true;
                }
                node = node.left;
            }
            else if (cmp > 0) {
                if (p.compareTo(new Point2D(node.x, node.y)) == 0) {
                    found = true;
                }
                node = node.right;
            }
            else found = true;
        }
        return found;
    }

    public void draw()                         // draw all points to standard draw
    {
        ArrayList<Point2D> q = new ArrayList<Point2D>();
        inorder(root, q);
        Iterator<Point2D> itr = q.iterator();
        while (itr.hasNext() == true) {
            Point2D pt1 = itr.next();
            pt1.draw();
            if (itr.hasNext() == true) {
                Point2D pt2 = itr.next();
                pt2.draw();
            }
        }
    }

    private void inorder(Node node, ArrayList<Point2D> q) {
        if (node == null) return;
        inorder(node.left, q);
        q.add(new Point2D(node.x, node.y));
        inorder(node.right, q);
    }


    private void range_traversal(double reflowx, double reflowy,
                                 double refhix, double refhiy,
                                 Node node, ArrayList<Point2D> vec) {
        if (node == null) return;
        double x = node.x;
        double y = node.y;


        //if (x < reflowx || x > refhix || y < reflowy || y > refhiy) return;
        if (x >= reflowx && x <= refhix && y >= reflowy && y <= refhiy)
            vec.add(new Point2D(node.x, node.y));
        range_traversal(reflowx, reflowy, refhix, refhiy, node.left, vec);
        range_traversal(reflowx, reflowy, refhix, refhiy, node.right, vec);
    }


    public Iterable<Point2D> range(
            RectHV rect)             // all points that are inside the rectangle (or on the boundary)
    {
        if (rect == null) throw new IllegalArgumentException();
        ArrayList<Point2D> q = new ArrayList<Point2D>();

        double lowx = Math.min(rect.xmin(), rect.xmax());
        double lowy = Math.min(rect.ymin(), rect.ymax());
        double hix = Math.max(rect.xmin(), rect.xmax());
        double hiy = Math.max(rect.ymin(), rect.ymax());

        /** check if we have to search on the left of right
         * 1. if rect is on the left, check left only
         * 2. if rect is on the right , check right only
         * 3. if root is in the rect, search both
         * */
        /* case 3 */
        if (root != null) {
            if (root.x >= lowx && root.x <= hix) {
                range_traversal(lowx, lowy, hix, hiy, root, q);
            }
            else if (root.x > rect.xmax()) {
                range_traversal(lowx, lowy, hix, hiy, root.left, q);
            }
            else {
                range_traversal(lowx, lowy, hix, hiy, root.right, q);
            }
        }
        return q;
    }


    private void range_traversal(Point2D pt, Node node, ArrayList<Point2D> vec) {
        if (node == null) return;

        if (vec.isEmpty()) {
            vec.add(0, new Point2D(node.x, node.y));
        }

        Point2D p = vec.get(0);

        double dist = pt.distanceSquaredTo(new Point2D(node.x, node.y));
        double refDist = pt.distanceSquaredTo(p);
        /*update the minimum */
        if (refDist > dist) {
            vec.add(0, new Point2D(node.x, node.y));
        }
        range_traversal(pt, node.left, vec);
        range_traversal(pt, node.right, vec);
    }

    public Point2D nearest(
            Point2D p)             // a nearest neighbor in the set to point p; null if the set is empty
    {
        Point2D point = null;
        ArrayList<Point2D> q = new ArrayList<Point2D>();
        if (p == null) throw new IllegalArgumentException();
        range_traversal(p, root, q);
        if (q.isEmpty())
            point = null;
        else
            point = q.get(0);
        return point;
    }

    public static void main(
            String[] args)                  // unit testing of the methods (optional)
    {

    }
}
