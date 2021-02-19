use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::reject::Reject;
use warp::reply::Reply;
use warp::{Filter, Rejection};

/// Create a new ratelimiting filter with the given parameters.
///
/// # Example
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     // Memory for filter
///     let mem = Arc::new(Mutex::new(Vec::new()));
///     // Ratelimiting filter that lets in 10 requests from each user every 6 minutes
///     let filter = warp_ratelimit::ratelimit_filter(Arc::clone(&mem), 10, Duration::new(360, 0)).await;
///     // Keep requesting filter until it stops letting requests through
///     let mut num_calls = 1;
///     let mut response = warp::test::request()
///         .remote_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080))
///         .reply(&filter)
///         .await;
///     while format!("{:?}", response).contains("200") {
///         response = warp::test::request()
///             .remote_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080))
///             .reply(&filter)
///             .await;
///         num_calls += 1;
///     }
///     // Amount of requests let through should be 10
///     assert_eq!(num_calls, 10);
/// }
/// ```
pub async fn ratelimit_filter(
    prev_visitors: Arc<Mutex<Vec<DistinctVisitor>>>,
    num_allowed_requests: u64,
    reset_duration: Duration,
) -> BoxedFilter<(impl Reply,)> {
    let prev_visitors_clone = Arc::clone(&prev_visitors);
    let ip_header = warp::header("X-Forwarded-For").and_then(move |ip_path: String| {
        let prev_visitors_clone = Arc::clone(&prev_visitors_clone);
        async move {
            let first_ip = ip_path.split(",").collect::<Vec<&str>>()[0];
            let addr_ip: IpAddr = match first_ip.parse() {
                Ok(ip) => ip,
                Err(_) => return Err(warp::reject::custom(InvalidXForwardedFor)),
            };
            let mut visitors_lock = prev_visitors_clone.lock().unwrap();
            let mut to_remove = Vec::new();
            let mut curr_visitor_found = false;
            for idx in 0..visitors_lock.len() {
                let visitor = &mut (*visitors_lock)[idx];
                if visitor.ip == addr_ip {
                    curr_visitor_found = true;
                    if visitor.first_request_time.elapsed() > reset_duration {
                        (*visitor).num_requests = 1;
                        (*visitor).first_request_time = Instant::now();
                        continue;
                    } else if visitor.num_requests + 1 >= num_allowed_requests {
                        return Ok(warp::reply::with_status(
                            "Too many requests".to_owned(),
                            StatusCode::TOO_MANY_REQUESTS,
                        ));
                    } else {
                        (*visitor).num_requests += 1;
                    }
                } else {
                    if visitor.first_request_time.elapsed() > reset_duration {
                        to_remove.push(idx);
                        continue;
                    }
                }
            }
            for remove in to_remove {
                (*visitors_lock).remove(remove);
            }
            if !curr_visitor_found {
                (*visitors_lock).push(DistinctVisitor {
                    first_request_time: Instant::now(),
                    num_requests: 1,
                    ip: addr_ip,
                });
            }
            Ok(warp::reply::with_status("".to_owned(), StatusCode::OK))
        }
    });
    let ip_normal = warp::filters::addr::remote().and_then(move |addr: Option<SocketAddr>| {
        let prev_visitors_clone = Arc::clone(&prev_visitors);
        async move {
            if let Some(addr) = addr {
                let addr_ip = addr.ip();
                let mut visitors_lock = prev_visitors_clone.lock().unwrap();
                let mut to_remove = Vec::new();
                let mut curr_visitor_found = false;
                for idx in 0..visitors_lock.len() {
                    let visitor = &mut (*visitors_lock)[idx];
                    if visitor.ip == addr_ip {
                        curr_visitor_found = true;
                        if visitor.first_request_time.elapsed() > reset_duration {
                            (*visitor).num_requests = 1;
                            (*visitor).first_request_time = Instant::now();
                            continue;
                        } else if visitor.num_requests + 1 >= num_allowed_requests {
                            return Ok::<_, Rejection>(warp::reply::with_status(
                                "Too many requests".to_owned(),
                                StatusCode::TOO_MANY_REQUESTS,
                            ));
                        } else {
                            (*visitor).num_requests += 1;
                        }
                    } else {
                        if visitor.first_request_time.elapsed() > reset_duration {
                            to_remove.push(idx);
                            continue;
                        }
                    }
                }
                for remove in to_remove {
                    (*visitors_lock).remove(remove);
                }
                if !curr_visitor_found {
                    (*visitors_lock).push(DistinctVisitor {
                        first_request_time: Instant::now(),
                        num_requests: 1,
                        ip: addr_ip,
                    });
                }
                Ok(warp::reply::with_status("".to_owned(), StatusCode::OK))
            } else {
                Err(warp::reject::reject())
            }
        }
    });
    ip_header
        .or(ip_normal)
        .unify()
        .recover(|rejection: Rejection| async move {
            if rejection.find::<InvalidXForwardedFor>().is_none() {
                return Ok(warp::reply::with_status("", StatusCode::BAD_REQUEST));
            }
            Err(warp::reject::reject())
        })
        .boxed()
}

/// A single distinct visitor for the filter to keep track of.
///
/// # Example
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     // Memory for filter
///     let mem = Arc::new(Mutex::new(Vec::new()));
///     // Ratelimiting filter that lets in 10 requests from each user every 6 minutes
///     let filter = warp_ratelimit::ratelimit_filter(Arc::clone(&mem), 10, Duration::new(360, 0)).await;
///     warp::test::request()
///         .remote_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080))
///         .reply(&filter)
///         .await;
///     // Memory should contain single visitor
///     let mem_lock = mem.lock().unwrap();
///     assert_eq!((*mem_lock).len(), 1);
///     let first_elem = (*mem_lock)[0].clone();
///     assert_eq!(first_elem.ip, Ipv4Addr::new(1, 1, 1, 1));
///     assert_eq!(first_elem.num_requests, 1);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistinctVisitor {
    pub first_request_time: Instant,
    pub num_requests: u64,
    pub ip: IpAddr,
}

#[derive(Debug)]
pub(crate) struct InvalidXForwardedFor;

impl Reject for InvalidXForwardedFor {}

#[cfg(test)]
mod tests {

    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn basic_ratelimit() {
        let mem = Arc::new(Mutex::new(Vec::new()));
        let filter = ratelimit_filter(Arc::clone(&mem), 10, Duration::new(360, 0)).await;
        let mut num_calls = 1;
        let mut response = warp::test::request()
            .remote_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080))
            .reply(&filter)
            .await;
        // Can't get status code of Response, please make PR
        while format!("{:?}", response).contains("200") {
            response = warp::test::request()
                .remote_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080))
                .reply(&filter)
                .await;
            num_calls += 1;
        }
        assert_eq!(num_calls, 10);
    }
}
