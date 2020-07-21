import edu.princeton.cs.algs4.StdOut;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Vector;


public class BruteCollinearPoints {
    private Point[] points;
    private LineSegment[] lineSegments;
    private int numberOfSegments;
    private LineSegment[] tempLineSegments;
    private Vector<PointSlope> pointSlopes;
    final private int max_slopes = 3;
    private Vector<LineSegment> lineSegmentVector;

    /**
     * create a private class to store a map of point and slope
     */
    private class PointSlope {
        public double slope;
        public Point point;
        public Point point2;
        public double equiDist;
        public LineSegment lineSegment;


        /**
         * equilidian distance between two points
         */
        //private double distance(Point ths, Point that) {
        //    return Math.sqrt(Math.pow((ths.x - that.x), 2) + Math.pow((ths.y - that.y), 2));
        //}
        public PointSlope(Point point, double slope) {
            this.point = point;
            this.slope = slope;
        }

        public PointSlope(Point point, Point point2, double slope) {
            this.point = point;
            this.point2 = point2;
            this.slope = slope;
            lineSegment = new LineSegment(point, point2);
            //this.equiDist = point.distance(point, point2);
        }
    }


    /**
     * return true if this segment is available in the segments.
     * two segments are equal if segment contains, both the points, order doesnt matter
     */
    private boolean DuplicateSegment(PointSlope pointSlope) {
        boolean found = false;
        for (int i = 0; i < pointSlopes.size(); i++) {
            if ((pointSlopes.get(i).point.compareTo(pointSlope.point) == 0 ||
                    pointSlopes.get(i).point.compareTo(pointSlope.point2) == 0) &&
                    (pointSlopes.get(i).point2.compareTo(pointSlope.point) == 0 ||
                            pointSlopes.get(i).point2.compareTo(pointSlope.point2) == 0)) {
                found = true;
                break;
            }
        }
        return found;
    }


    /**
     * search for segments
     *
     * @return vector of same slope PointSlope objects
     */
    /*
    private Vector<PointSlope> CollinearPoints() {
        int sameSlopes = 0;
        Vector<PointSlope> vec = new Vector<PointSlope>();
        for (int j = 0; j < pointSlopes.length - 1; j++) {
            double slope = pointSlopes[j].slope;
            vec.add(pointSlopes[j]);
            for (int k = j + 1; k < pointSlopes.length; k++) {
                if (slope == pointSlopes[k].slope) {
                    ++sameSlopes;
                    vec.add(pointSlopes[k]);
                }
                if (sameSlopes >= max_slopes) {
                    break;
                } else {
                    vec.clear();
                }
            }
        }
        return vec;
    }
     */
    private void PrintSlopePoints(Vector<PointSlope> pointSlopes) {
        /*print the slopes */
        for (int i = 0; i < pointSlopes.size(); i++) {
            LineSegment segment = pointSlopes.get(i).lineSegment;
            StdOut.print(i + ":" + " " + segment + "  ");
            //StdOut.println(pointSlopes.get(i).slope);
            System.out.printf("slope %.2f    %.2f", pointSlopes.get(i).slope, pointSlopes.get(i).equiDist);
            StdOut.println();
        }
    }


    private void SortMergePointSlope(Vector<PointSlope> a, Vector<PointSlope> aux, int lo, int mid, int hi) {
        aux.clear();
        aux = new Vector<PointSlope>(a);
        int i = lo, j = mid + 1;
        for (int k = lo; k <= hi; k++) {
            if (i > mid) a.set(k, aux.get(j++));
            else if (j > hi) a.set(k, aux.get(i++));
            else if (aux.get(j).slope <= aux.get(i).slope) a.set(k, aux.get(j++));
            else a.set(k, aux.get(i++));
        }
    }

    private Vector<PointSlope> sort(Vector<PointSlope> a) {
        int N = a.size();
        Vector<PointSlope> aux = new Vector<PointSlope>(a);
        //System.out.println("aux capacity is " + aux.size());
        for (int sz = 1; sz < N; sz = sz + sz) {
            for (int lo = 0; lo < N - sz; lo += sz + sz) {
                SortMergePointSlope(a, aux, lo, lo + sz - 1, Math.min(lo + sz + sz - 1, N - 1));
            }
        }
        return a;
    }

    /**
     * sort the pointslopes wrt to slope.
     *
     * @param pointSlopes
     */
    private void SortPointSlope(Vector<PointSlope> pointSlopes) {
        //System.out.println("sorting point slopes: " + pointSlopes.size());
        int i = 0;
        int j = 0;
        for (i = 0; i < pointSlopes.size() - 1; i++) {
            for (j = i + 1; j < pointSlopes.size(); j++) {
                if (pointSlopes.get(j).slope <= pointSlopes.get(i).slope) {
                    PointSlope temp = pointSlopes.get(i);
                    pointSlopes.set(i, pointSlopes.get(j));
                    pointSlopes.set(j, temp);
                }
            }
        }
    }

    /**
     * sort the points wrt to y-axis breaking ties with x-axis.
     *
     * @param pointSlopes
     */
    private void SortPoint(Vector<PointSlope> pointSlopes) {
        //System.out.println("Sorting points");
        for (int i = 0; i < pointSlopes.size() - 1; i++) {
            Point point1 = pointSlopes.get(i).point;
            for (int j = i + 1; j < pointSlopes.size(); j++) {
                Point point2 = pointSlopes.get(j).point;
                if (point2.compareTo(point1) <= 0) {
                    PointSlope temp = pointSlopes.get(i);
                    pointSlopes.set(i, pointSlopes.get(j));
                    pointSlopes.set(j, temp);
                    point1 = pointSlopes.get(i).point;

                }
            }
        }
    }

    /**
     * sort the input points
     *
     * @param points
     */
    private void SortPoint(Point[] points) {
        //System.out.println("Sorting points");
        for (int i = 0; i < points.length - 1; i++) {
            Point point1 = points[i];
            for (int j = i + 1; j < points.length; j++) {
                Point point2 = points[j];
                if (point2.compareTo(point1) <= 0) {
                    Point temp = points[i];
                    points[i] = points[j];
                    points[j] = temp;
                    point1 = points[i];
                }
            }
        }
    }

    private void SelectMaxSegment(Vector<PointSlope> pointSlopes) {
        double maxLength = 0.0;
        int maxSegment = 0;

        Point point2 = pointSlopes.get(0).point2;
        assert (pointSlopes.size() >= max_slopes);
        for (int i = 0; i < pointSlopes.size(); i++) {
            if (pointSlopes.get(i).point2.compareTo(point2) >= 0) {
                point2 = pointSlopes.get(i).point2;
                maxSegment = i;
            }
        }
        //StdOut.println(pointSlopes.get(maxSegment).lineSegment);
        lineSegmentVector.add(pointSlopes.get(maxSegment).lineSegment);
        //System.out.println("did we come here");
    }


    /**
     * gorup the same slope segments with numbers more than 3
     *
     * @param points
     */
    private void GroupSegments(Vector<PointSlope> pointSlopes) {
        int count = 0;
        int i = 0;
        Vector<PointSlope> temp = new Vector<PointSlope>();
        while (i < (pointSlopes.size() - 1)) {
            PointSlope pointSlope1 = pointSlopes.get(i);
            temp.add(pointSlope1);
            for (int j = i + 1; j < pointSlopes.size(); j++) {
                i = j;
                PointSlope pointSlope2 = pointSlopes.get(j);
                if (pointSlope1.point.compareTo(pointSlope2.point) == 0 &&
                        pointSlope1.slope == pointSlope2.slope) {
                    temp.add(pointSlope2);
                } else {
                    if (temp.size() >= max_slopes)
                        SelectMaxSegment(temp);
                    temp.clear();
                    break;
                }
            }
        }
        if (temp.size() >= max_slopes)
            SelectMaxSegment(temp);
        temp.clear();
    }

    /**
     * comprate two points to be same
     */
    private boolean IsEqual(Point ths, Point that) {
        return false;
    }


    public BruteCollinearPoints(Point[] points) {
        this.points = points;
        numberOfSegments = 0;

        if (points == null) throw new java.lang.IllegalArgumentException();

        for (int k = 0; k < points.length; k++) {
            if (points[k] == null) throw new java.lang.IllegalArgumentException();
        }
        Arrays.sort(points);//, new Comparable<Point>());
        pointSlopes = new Vector<PointSlope>();
        PointSlope pointSlope;
        lineSegmentVector = new Vector<LineSegment>();
        for (int i = 0; i < points.length - 1; i++) {
            for (int j = i + 1; j < points.length; j++) {
                if (i != j) {
                    //if (points[i] == null || points[j] == null) throw new java.lang.IllegalArgumentException();
                    if (points[i].compareTo(points[j]) == 0) throw new java.lang.IllegalArgumentException();

                    pointSlope = new PointSlope(points[i], points[j], points[i].slopeTo(points[j]));
                    /**
                     * add this new segment only if its not there
                     */
                    //if (DuplicateSegment(pointSlope) == false) {
                    pointSlopes.add(pointSlope);
                    //}
                }
            }
        }
        //SortPointSlope(pointSlopes);
        //System.out.println("Print sorted slopes");
        //PrintSlopePoints(pointSlopes);
        Vector<PointSlope> sortedPointSlopes = sort(pointSlopes);

        //SortPoint(pointSlopes);
        //System.out.println("Print sorted Points");
        //PrintSlopePoints(pointSlopes);
        //GroupSegments(pointSlopes);
        GroupSegments(sortedPointSlopes);
    }


    private class LineSegmentIterator implements Iterator<LineSegment> {
        private int totalCount = lineSegmentVector.size();
        private int i = 0;

        public boolean hasNext() {
            return i < totalCount;
        }

        public LineSegment next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            LineSegment lineSegment = lineSegmentVector.get(i);
            i++;
            return lineSegment;
        }
    }

    public int numberOfSegments() {
        return lineSegmentVector.size();

    }


    private Iterator<LineSegment> iterator() {
        return new LineSegmentIterator();
    }

    private Iterable<LineSegment> segment() {
        return new Iterable<LineSegment>() {
            public Iterator<LineSegment> iterator() {
                return new LineSegmentIterator();
            }
        };
    }

    public LineSegment[] segments() {
        return lineSegmentVector.toArray(new LineSegment[lineSegmentVector.size()]);
    }
}
