import java.util.Iterator;
import java.util.Vector;

public class BruteCollinearPoints {
    private Point[] points;
    private LineSegment[] lineSegments;
    private int numberOfSegments;
    private LineSegment[] tempLineSegments;
    private PointSlope[] pointSlopes;
    final private int max_slopes = 4;

    /**
     * create a private class to store a map of point and slope
     */
    private class PointSlope {
        public double slope;
        public Point point;
        public Point point2;

        public PointSlope(Point point, Double slope) {
            this.point = point;
            this.slope = slope;
        }

        public PointSlope(Point point, Point point2, Double slope) {
            this.point = point;
            this.point2 = point2;
            this.slope = slope;
        }
    }

    /**
     * search for segments
     *
     * @return vector of same slope PointSlope objects
     */
    private Vector Segments() {
        int sameSlopes = 0;
        Vector vec = new Vector()
        for (int j = 0; j < pointSlopes.length - 1; j++) {
            double slope = pointSlopes[j].slope;
            vec.add(pointSlopes[j])
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


    private void Sort(PointSlope[] pointSlopes) {
        int i = 0;
        int j = 0;
        for (i = 0; i < pointSlopes.length - 1; i++)
            for (j = i + 1; i < pointSlopes.length; j++) {
                if (pointSlopes[j].slope <= pointSlopes[i].slope) {
                    PointSlope temp = pointSlopes[i];
                    pointSlopes[i] = pointSlopes[j];
                    pointSlopes[j] = temp;
                    break;
                }
            }
    }

    BruteCollinearPoints(Point[] points) {
        int k = 0;
        this.points = points;
        numberOfSegments = 0;
        pointSlopes = new PointSlope[points.length - 1];
        lineSegments = new LineSegment[points.length];
        for (int i = 0; i < points.length; i++) {
            k = 0;
            for (int j = 0; j < points.length; j++) {
                if (points[i].IsEqual(points[j]) == false) {
                    pointSlopes[k] = new PointSlope(points[i], points[j], points[i].slopeTo(points[j]));
                    k++;
                }
            }
            //System.out.println("number of segments " + numberOfSegments);
            // sort the elements in the oder
            Sort(pointSlopes);
            // find 3 points that made the same angle to this point
            Vector vec = Segments();
            if (vec.size() >= max_slopes) {


            }


        }
    }


    private class LineSegmentIterator implements Iterator<LineSegment> {
        private LineSegment[] segments = lineSegments;
        private int totalCount = numberOfSegments;
        private int i = 0;

        public boolean hasNext() {
            return i < totalCount;
        }

        public LineSegment next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            return this.segments[i++];
        }
    }


    public Iterator<LineSegment> iterator() {
        return new LineSegmentIterator();
    }

    public Iterable<LineSegment> segments() {
        return new Iterable<LineSegment>() {
            public Iterator<LineSegment> iterator() {
                return new LineSegmentIterator();
            }
        };
    }
}
